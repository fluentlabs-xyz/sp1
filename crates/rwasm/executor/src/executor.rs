use std::{
    fs::File,
    io::{BufWriter, Write},
    ops::Shl,
    sync::Arc,
};

use hashbrown::HashMap;
use num::Signed;
use serde::{Deserialize, Serialize};
use sp1_stark::SP1CoreOpts;
use thiserror::Error;

use crate::{
    context::SP1Context,
    dependencies::{emit_cpu_dependencies, emit_divrem_dependencies},
    events::{
        create_alu_lookup_id, create_alu_lookups, AluEvent, CpuEvent, LookupId,
        MemoryInitializeFinalizeEvent, MemoryLocalEvent, MemoryReadRecord,
        MemoryRecord, MemoryWriteRecord, SyscallEvent,
    },
    hook::{HookEnv, HookRegistry},
    memory::{Entry, PagedMemory},
    record::ExecutionRecord,
    report::ExecutionReport,
    state::{ExecutionState, ForkState},
    subproof::{DefaultSubproofVerifier, SubproofVerifier},
    syscalls::{default_syscall_map, Syscall, SyscallCode, SyscallContext},
    Opcode, Program, Register, SP_START,
};

use rwasm::engine::bytecode::Instruction;

/// An executor for the SP1 RISC-V zkVM.
///
/// The exeuctor is responsible for executing a user program and tracing important events which
/// occur during execution (i.e., memory reads, alu operations, etc).
#[repr(C)]
pub struct Executor<'a> {
    /// The program.
    pub program: Arc<Program>,

    /// The mode the executor is running in.
    pub executor_mode: ExecutorMode,

    /// Whether the runtime is in constrained mode or not.
    ///
    /// In unconstrained mode, any events, clock, register, or memory changes are reset after
    /// leaving the unconstrained block. The only thing preserved is writes to the input
    /// stream.
    pub unconstrained: bool,

    /// Whether we should write to the report.
    pub print_report: bool,

    /// The maximum size of each shard.
    pub shard_size: u32,

    /// The maximum number of shards to execute at once.
    pub shard_batch_size: u32,

    /// The maximum number of cycles for a syscall.
    pub max_syscall_cycles: u32,

    /// The mapping between syscall codes and their implementations.
    pub syscall_map: HashMap<SyscallCode, Arc<dyn Syscall>>,

    /// The options for the runtime.
    pub opts: SP1CoreOpts,

    /// Memory addresses that were touched in this batch of shards. Used to minimize the size of
    /// checkpoints.
    pub memory_checkpoint: PagedMemory<Option<MemoryRecord>>,

    /// Memory addresses that were initialized in this batch of shards. Used to minimize the size of
    /// checkpoints. The value stored is whether or not it had a value at the beginning of the batch.
    pub uninitialized_memory_checkpoint: PagedMemory<bool>,

    /// The maximum number of cpu cycles to use for execution.
    pub max_cycles: Option<u64>,

    /// The state of the execution.
    pub state: ExecutionState,

    /// The current trace of the execution that is being collected.
    pub record: ExecutionRecord,

    /// The collected records, split by cpu cycles.
    pub records: Vec<ExecutionRecord>,

    /// Local memory access events.
    pub local_memory_access: HashMap<u32, MemoryLocalEvent>,

    /// A counter for the number of cycles that have been executed in certain functions.
    pub cycle_tracker: HashMap<String, (u64, u32)>,

    /// A buffer for stdout and stderr IO.
    pub io_buf: HashMap<u32, String>,

    /// A buffer for writing trace events to a file.
    pub trace_buf: Option<BufWriter<File>>,

    /// The state of the runtime when in unconstrained mode.
    pub unconstrained_state: ForkState,

    /// Report of the program execution.
    pub report: ExecutionReport,

    /// Verifier used to sanity check `verify_sp1_proof` during runtime.
    pub subproof_verifier: Arc<dyn SubproofVerifier + 'a>,

    /// Registry of hooks, to be invoked by writing to certain file descriptors.
    pub hook_registry: HookRegistry<'a>,

    /// The maximal shapes for the program.
    pub maximal_shapes: Option<Vec<HashMap<String, usize>>>,
}

/// The different modes the executor can run in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecutorMode {
    /// Run the execution with no tracing or checkpointing.
    Simple,
    /// Run the execution with checkpoints for memory.
    Checkpoint,
    /// Run the execution with full tracing of events.
    Trace,
}

/// Errors that the [``Executor``] can throw.
#[derive(Error, Debug, Serialize, Deserialize)]
pub enum ExecutionError {
    /// The execution failed with a non-zero exit code.
    #[error("execution failed with exit code {0}")]
    HaltWithNonZeroExitCode(u32),

    /// The execution failed with an invalid memory access.
    #[error("invalid memory access for opcode {0} and address {1}")]
    InvalidMemoryAccess(Opcode, u32),

    /// The execution failed with an unimplemented syscall.
    #[error("unimplemented syscall {0}")]
    UnsupportedSyscall(u32),

    /// The execution failed with a breakpoint.
    #[error("breakpoint encountered")]
    Breakpoint(),

    /// The execution failed with an exceeded cycle limit.
    #[error("exceeded cycle limit of {0}")]
    ExceededCycleLimit(u64),

    /// The execution failed because the syscall was called in unconstrained mode.
    #[error("syscall called in unconstrained mode")]
    InvalidSyscallUsage(u64),

    /// The execution failed with an unimplemented feature.
    #[error("got unimplemented as opcode")]
    Unimplemented(),

    /// The program ended in unconstrained mode.
    #[error("program ended in unconstrained mode")]
    EndInUnconstrained(),
}

macro_rules! assert_valid_memory_access {
    ($addr:expr, $position:expr) => {
        #[cfg(not(debug_assertions))]
        {}
    };
}

impl<'a> Executor<'a> {
    /// Create a new [``Executor``] from a program and options.
    #[must_use]
    pub fn new(program: Program, opts: SP1CoreOpts) -> Self {
        Self::with_context(program, opts, SP1Context::default())
    }

    /// Create a new runtime from a program, options, and a context.
    ///
    /// # Panics
    ///
    /// This function may panic if it fails to create the trace file if `TRACE_FILE` is set.
    #[must_use]
    pub fn with_context(program: Program, opts: SP1CoreOpts, context: SP1Context<'a>) -> Self {
        // Create a shared reference to the program.
        let program = Arc::new(program);

        // Create a default record with the program.
        let record = ExecutionRecord::new(program.clone());

        // If `TRACE_FILE`` is set, initialize the trace buffer.
        let trace_buf = if let Ok(trace_file) = std::env::var("TRACE_FILE") {
            let file = File::create(trace_file).unwrap();
            Some(BufWriter::new(file))
        } else {
            None
        };

        // Determine the maximum number of cycles for any syscall.
        let syscall_map = default_syscall_map();
        let max_syscall_cycles =
            syscall_map.values().map(|syscall| syscall.num_extra_cycles()).max().unwrap_or(0);

        let subproof_verifier =
            context.subproof_verifier.unwrap_or_else(|| Arc::new(DefaultSubproofVerifier::new()));
        let hook_registry = context.hook_registry.unwrap_or_default();

        Self {
            record,
            records: vec![],
            state: ExecutionState::new(program.pc_start),
            program,

            shard_size: (opts.shard_size as u32) * 4,
            shard_batch_size: opts.shard_batch_size as u32,
            cycle_tracker: HashMap::new(),
            io_buf: HashMap::new(),
            trace_buf,
            unconstrained: false,
            unconstrained_state: ForkState::default(),
            syscall_map,
            executor_mode: ExecutorMode::Trace,
            max_syscall_cycles,
            report: ExecutionReport::default(),
            print_report: false,
            subproof_verifier,
            hook_registry,
            opts,
            max_cycles: context.max_cycles,
            memory_checkpoint: PagedMemory::new_preallocated(),
            uninitialized_memory_checkpoint: PagedMemory::new_preallocated(),
            local_memory_access: HashMap::new(),
            maximal_shapes: None,
        }
    }

    /// Invokes a hook with the given file descriptor `fd` with the data `buf`.
    ///
    /// # Errors
    ///
    /// If the file descriptor is not found in the [``HookRegistry``], this function will return an
    /// error.
    pub fn hook(&self, fd: u32, buf: &[u8]) -> eyre::Result<Vec<Vec<u8>>> {
        Ok(self
            .hook_registry
            .get(fd)
            .ok_or(eyre::eyre!("no hook found for file descriptor {}", fd))?
            .invoke_hook(self.hook_env(), buf))
    }

    /// Prepare a `HookEnv` for use by hooks.
    #[must_use]
    pub fn hook_env<'b>(&'b self) -> HookEnv<'b, 'a> {
        HookEnv { runtime: self }
    }

    /// Recover runtime state from a program and existing execution state.
    #[must_use]
    pub fn recover(program: Program, state: ExecutionState, opts: SP1CoreOpts) -> Self {
        let mut runtime = Self::new(program, opts);
        runtime.state = state;
        runtime
    }

    /// Get the current value of a word.
    #[must_use]
    pub fn word(&mut self, addr: u32) -> u32 {
        #[allow(clippy::single_match_else)]
        let record = self.state.memory.get(addr);

        if self.executor_mode == ExecutorMode::Checkpoint || self.unconstrained {
            match record {
                Some(record) => {
                    self.memory_checkpoint.entry(addr).or_insert_with(|| Some(*record));
                }
                None => {
                    self.memory_checkpoint.entry(addr).or_insert(None);
                }
            }
        }

        match record {
            Some(record) => record.value,
            None => 0,
        }
    }

    /// Get the current value of a byte.
    #[must_use]
    pub fn byte(&mut self, addr: u32) -> u8 {
        let word = self.word(addr - addr % 4);
        (word >> ((addr % 4) * 8)) as u8
    }

    /// Get the current timestamp for a given memory access position.
    #[must_use]
    pub const fn timestamp(&self) -> u32 {
        self.state.clk 
    }

    /// Get the current shard.
    #[must_use]
    #[inline]
    pub fn shard(&self) -> u32 {
        self.state.current_shard
    }

    /// Read a word from memory and create an access record.
    pub fn mr(
        &mut self,
        addr: u32,
        shard: u32,
        timestamp: u32,
        local_memory_access: Option<&mut HashMap<u32, MemoryLocalEvent>>,
    ) -> MemoryReadRecord {
        // Get the memory record entry.
        let entry = self.state.memory.entry(addr);
        if self.executor_mode == ExecutorMode::Checkpoint || self.unconstrained {
            match entry {
                Entry::Occupied(ref entry) => {
                    let record = entry.get();
                    self.memory_checkpoint.entry(addr).or_insert_with(|| Some(*record));
                }
                Entry::Vacant(_) => {
                    self.memory_checkpoint.entry(addr).or_insert(None);
                }
            }
        }

        // If we're in unconstrained mode, we don't want to modify state, so we'll save the
        // original state if it's the first time modifying it.
        if self.unconstrained {
            let record = match entry {
                Entry::Occupied(ref entry) => Some(entry.get()),
                Entry::Vacant(_) => None,
            };
            self.unconstrained_state.memory_diff.entry(addr).or_insert(record.copied());
        }

        // If it's the first time accessing this address, initialize previous values.
        let record: &mut MemoryRecord = match entry {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                // If addr has a specific value to be initialized with, use that, otherwise 0.
                let value = self.state.uninitialized_memory.get(addr).unwrap_or(&0);
                self.uninitialized_memory_checkpoint.entry(addr).or_insert_with(|| *value != 0);
                entry.insert(MemoryRecord { value: *value, shard: 0, timestamp: 0 })
            }
        };

        let prev_record = *record;
        record.shard = shard;
        record.timestamp = timestamp;

        if !self.unconstrained {
            let local_memory_access = if let Some(local_memory_access) = local_memory_access {
                local_memory_access
            } else {
                &mut self.local_memory_access
            };

            local_memory_access
                .entry(addr)
                .and_modify(|e| {
                    e.final_mem_access = *record;
                })
                .or_insert(MemoryLocalEvent {
                    addr,
                    initial_mem_access: prev_record,
                    final_mem_access: *record,
                });
        }

        // Construct the memory read record.
        MemoryReadRecord::new(
            record.value,
            record.shard,
            record.timestamp,
            prev_record.shard,
            prev_record.timestamp,
        )
    }

    /// Write a word to memory and create an access record.
    pub fn mw(
        &mut self,
        addr: u32,
        value: u32,
        shard: u32,
        timestamp: u32,
        local_memory_access: Option<&mut HashMap<u32, MemoryLocalEvent>>,
    ) -> MemoryWriteRecord {
        // Get the memory record entry.
        let entry = self.state.memory.entry(addr);
        if self.executor_mode == ExecutorMode::Checkpoint || self.unconstrained {
            match entry {
                Entry::Occupied(ref entry) => {
                    let record = entry.get();
                    self.memory_checkpoint.entry(addr).or_insert_with(|| Some(*record));
                }
                Entry::Vacant(_) => {
                    self.memory_checkpoint.entry(addr).or_insert(None);
                }
            }
        }

        // If we're in unconstrained mode, we don't want to modify state, so we'll save the
        // original state if it's the first time modifying it.
        if self.unconstrained {
            let record = match entry {
                Entry::Occupied(ref entry) => Some(entry.get()),
                Entry::Vacant(_) => None,
            };
            self.unconstrained_state.memory_diff.entry(addr).or_insert(record.copied());
        }

        // If it's the first time accessing this address, initialize previous values.
        let record: &mut MemoryRecord = match entry {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                // If addr has a specific value to be initialized with, use that, otherwise 0.
                let value = self.state.uninitialized_memory.get(addr).unwrap_or(&0);
                self.uninitialized_memory_checkpoint.entry(addr).or_insert_with(|| *value != 0);

                entry.insert(MemoryRecord { value: *value, shard: 0, timestamp: 0 })
            }
        };

        let prev_record = *record;
        record.value = value;
        record.shard = shard;
        record.timestamp = timestamp;

        if !self.unconstrained {
            let local_memory_access = if let Some(local_memory_access) = local_memory_access {
                local_memory_access
            } else {
                &mut self.local_memory_access
            };

            local_memory_access
                .entry(addr)
                .and_modify(|e| {
                    e.final_mem_access = *record;
                })
                .or_insert(MemoryLocalEvent {
                    addr,
                    initial_mem_access: prev_record,
                    final_mem_access: *record,
                });
        }

        // Construct the memory write record.
        MemoryWriteRecord::new(
            record.value,
            record.shard,
            record.timestamp,
            prev_record.value,
            prev_record.shard,
            prev_record.timestamp,
        )
    }

    fn fetch_unary_op_data(&mut self) -> Option<MemoryReadRecord> {
        let sp = self.state.sp;
        let clk = self.state.clk;
        let shard = self.shard();
        let arg1_record = self.mr(sp, shard, clk, None);

        Some(arg1_record)
    }

    fn fetch_binary_op_data(&mut self) -> (Option<MemoryReadRecord>, Option<MemoryReadRecord>) {
        let sp = self.state.sp;
        let clk = self.state.clk;
        let shard = self.shard();
        let arg1_record = self.mr(sp, shard, clk, None);
        let arg2_record = self.mr(sp - 4, shard, clk, None);
        (Some(arg1_record), Some(arg2_record))
    }

    fn write_back_res_to_stack(&mut self, res: u32, next_sp: u32) -> MemoryWriteRecord {
        self.state.clk += 4;
        self.state.sp = next_sp;
        self.mw(self.state.sp, res, self.shard(), self.state.clk, None)
    }

    fn write_back_res_to_memory(&mut self,res:u32,addr:u32,next_sp:u32)->MemoryWriteRecord{
        self.state.clk+=4;
        self.state.sp= next_sp;
        self.mw(addr, res, self.shard(),self.state.clk, None)
        
    }

    

    fn load_memory_value(&mut self,instruction: &Instruction,offset:u32)->
        Result<(MemoryReadRecord,MemoryReadRecord,u32),ExecutionError>{
            match instruction{
                Instruction::I32Load(_)|
                Instruction::I32Load16S(_)|
                Instruction::I32Load16U(_)|
                Instruction::I32Load8S(_)|
                Instruction::I32Load8U(_)=>{
                    let arg1_record=self.fetch_unary_op_data().unwrap();
                    let raw_addr = arg1_record.value;
                    let addr = offset.checked_add(raw_addr);  
                    match addr {
                        Some(addr)=>{
                            let sp = self.state.sp;
                            let clk = self.state.clk;
                            let shard = self.shard();
                            let arg2_record = self.mr(align(addr), shard, clk, None);
            
                            return  Ok((arg1_record,arg2_record,addr));
                           
                        }
                        None => {return Err(ExecutionError::InvalidMemoryAccess(Opcode::LW, offset))}
                    }
                }
                _=>unreachable!()

            }
            todo!()
    }

 

    /// Emit a CPU event.
    #[allow(clippy::too_many_arguments)]
    fn emit_cpu(
        &mut self,
        shard: u32,
        clk: u32,
        pc: u32,
        next_pc: u32,
        sp: u32,
        next_sp: u32,
        instruction: Instruction,
        arg1: u32,
        arg2: u32,
        res: u32,
        arg1_record: Option<MemoryReadRecord>,
        arg2_record: Option<MemoryReadRecord>,
        res_record: Option<MemoryWriteRecord>,
        exit_code: u32,
        lookup_id: LookupId,
        syscall_lookup_id: LookupId,
    ) {
        let cpu_event = CpuEvent {
            shard,
            clk,
            pc,
            next_pc,
            sp,
            next_sp,
            instruction,
            arg1,
            arg2,
            res,
            arg1_record,
            arg2_record,
            res_record,
            exit_code,
            alu_lookup_id: lookup_id,
            syscall_lookup_id,
            memory_add_lookup_id: create_alu_lookup_id(),
            memory_sub_lookup_id: create_alu_lookup_id(),
            branch_lt_lookup_id: create_alu_lookup_id(),
            branch_gt_lookup_id: create_alu_lookup_id(),
            branch_add_lookup_id: create_alu_lookup_id(),
            jump_jal_lookup_id: create_alu_lookup_id(),
            jump_jalr_lookup_id: create_alu_lookup_id(),
            auipc_lookup_id: create_alu_lookup_id(),
        };
        tracing::info!("cpu event: {:?}", cpu_event);
        self.record.cpu_events.push(cpu_event);
        emit_cpu_dependencies(self, &cpu_event);
    }

    /// Emit an ALU event.
    fn emit_alu(&mut self, clk: u32, opcode: Opcode, a: u32, b: u32, c: u32, lookup_id: LookupId) {
        let event = AluEvent {
            lookup_id,
            shard: self.shard(),
            clk,
            opcode,
            a,
            b,
            c,
            sub_lookups: create_alu_lookups(),
        };
        tracing::info!("aluevent{:?}", event);
        match opcode {
            Opcode::ADD => {
                self.record.add_events.push(event);
            }
            Opcode::SUB => {
                self.record.sub_events.push(event);
            }
            Opcode::XOR | Opcode::OR | Opcode::AND => {
                self.record.bitwise_events.push(event);
            }
            Opcode::SLL => {
                self.record.shift_left_events.push(event);
            }
            Opcode::SRL | Opcode::SRA => {
                self.record.shift_right_events.push(event);
            }
            Opcode::SLT | Opcode::SLTU => {
                self.record.lt_events.push(event);
            }
            Opcode::MUL | Opcode::MULHU | Opcode::MULHSU | Opcode::MULH => {
                self.record.mul_events.push(event);
            }
            Opcode::DIVU | Opcode::REMU | Opcode::DIV | Opcode::REM => {
                self.record.divrem_events.push(event);
                emit_divrem_dependencies(self, event);
            }
            _ => {}
        }
    }

    #[inline]
    pub(crate) fn syscall_event(
        &self,
        clk: u32,
        syscall_id: u32,
        arg1: u32,
        arg2: u32,
        lookup_id: LookupId,
    ) -> SyscallEvent {
        SyscallEvent {
            shard: self.shard(),
            clk,
            syscall_id,
            arg1,
            arg2,
            lookup_id,
            nonce: self.record.nonce_lookup[&lookup_id],
        }
    }

    fn emit_syscall(
        &mut self,
        clk: u32,
        syscall_id: u32,
        arg1: u32,
        arg2: u32,
        lookup_id: LookupId,
    ) {
        let syscall_event = self.syscall_event(clk, syscall_id, arg1, arg2, lookup_id);

        self.record.syscall_events.push(syscall_event);
    }

   

    /// Fetch the instruction at the current program counter.
    #[inline]
    fn fetch(&self) -> Instruction {
        let idx = ((self.state.pc - self.program.pc_base) / 4) as usize;
        self.program.instructions[idx]
    }

    /// Execute the given instruction over the current state of the runtime.
    #[allow(clippy::too_many_lines)]
    fn execute_instruction(&mut self, instruction: &Instruction) -> Result<(), ExecutionError> {
        let mut pc = self.state.pc;
        let mut clk = self.state.clk;
        let mut exit_code = 0u32;
        let mut sp = self.state.sp;
        let mut next_pc = self.state.pc.wrapping_add(4);
        let mut next_sp = sp; //we do not know the next_sp until we know the operator
        let (mut arg1, mut arg2, mut res): (u32, u32, u32) = (0, 0, 0);
        let mut arg1_record: Option<MemoryReadRecord> = None;
        let mut arg2_record: Option<MemoryReadRecord> = None;
        let mut res_record: Option<MemoryWriteRecord> = None;
        let mut res_is_writtten_back_to_stack: bool = false;
        if self.executor_mode == ExecutorMode::Trace {
            // TODO: add rwasm memory record
        }
        let lookup_id = if self.executor_mode == ExecutorMode::Trace {
            create_alu_lookup_id()
        } else {
            LookupId::default()
        };
        let syscall_lookup_id = if self.executor_mode == ExecutorMode::Trace {
            create_alu_lookup_id()
        } else {
            LookupId::default()
        };

        // if !self.unconstrained {
        //     self.report.opcode_counts[instruction.opcode] += 1;
        //     self.report.event_counts[instruction.opcode] += 1;
        //     match instruction.opcode {
        //         Opcode::LB | Opcode::LH | Opcode::LW | Opcode::LBU | Opcode::LHU => {
        //             self.report.event_counts[Opcode::ADD] += 2;
        //         }
        //         Opcode::JAL | Opcode::JALR | Opcode::AUIPC => {
        //             self.report.event_counts[Opcode::ADD] += 1;
        //         }
        //         Opcode::BEQ
        //         | Opcode::BNE
        //         | Opcode::BLT
        //         | Opcode::BGE
        //         | Opcode::BLTU
        //         | Opcode::BGEU => {
        //             self.report.event_counts[Opcode::ADD] += 1;
        //             self.report.event_counts[Opcode::SLTU] += 2;
        //         }
        //         Opcode::DIVU | Opcode::REMU | Opcode::DIV | Opcode::REM => {
        //             self.report.event_counts[Opcode::MUL] += 2;
        //             self.report.event_counts[Opcode::ADD] += 2;
        //             self.report.event_counts[Opcode::SLTU] += 1;
        //         }
        //         _ => {}
        //     };
        // }
        //TODO: fix report
        match instruction {
            Instruction::LocalGet(local_depth) => todo!(),
            Instruction::LocalSet(local_depth) => todo!(),
            Instruction::LocalTee(local_depth) => todo!(),
            Instruction::Br(branch_offset) => {
                next_pc =( pc as i32 +  branch_offset.to_i32()) as u32;
                res_is_writtten_back_to_stack = false;
                println!("pc:{}, next_pc:{}",pc,next_pc);
            },
            Instruction::BrIfEqz(branch_offset) => {
                
                arg1_record = self.fetch_unary_op_data();
                arg1 = arg1_record.unwrap().value;
                if arg1 ==0{
                    next_pc =( pc as i32 + branch_offset.to_i32()) as u32;
                }
                next_sp = sp-4;
                self.state.sp = next_sp;
                println!("BrIfEqz top:{}, offset:{} ,pc:{},next pc:{}",arg1,branch_offset.to_i32(),pc,next_pc);
            },
            Instruction::BrIfNez(branch_offset) => {
                arg1_record = self.fetch_unary_op_data();
                arg1 = arg1_record.unwrap().value;
                if arg1 !=0{
                    next_pc =( pc as i32 + branch_offset.to_i32()) as u32;
                }
                next_sp = sp-4;
                self.state.sp = next_sp;
                println!("BrIfNqz top:{}, offset:{} ,pc:{},next pc:{}",arg1,branch_offset.to_i32(),pc,next_pc);
            },
            Instruction::BrAdjust(branch_offset) => todo!(),
            Instruction::BrAdjustIfNez(branch_offset) => todo!(),
            Instruction::BrTable(branch_table_targets) => todo!(),
            Instruction::Unreachable => todo!(),
            Instruction::ConsumeFuel(block_fuel) => todo!(),
            Instruction::Return(drop_keep) => todo!(),
            Instruction::ReturnIfNez(drop_keep) => todo!(),
            Instruction::ReturnCallInternal(compiled_func) => todo!(),
            Instruction::ReturnCall(func_idx) => todo!(),
            Instruction::ReturnCallIndirect(signature_idx) => todo!(),
            Instruction::CallInternal(compiled_func) => todo!(),
            Instruction::Call(func_idx) => todo!(),
            Instruction::CallIndirect(signature_idx) => todo!(),
            Instruction::SignatureCheck(signature_idx) => todo!(),
            Instruction::Drop => todo!(),
            Instruction::Select => todo!(),
            Instruction::GlobalGet(global_idx) => todo!(),
            Instruction::GlobalSet(global_idx) => todo!(),
            Instruction::I32Load(address_offset) => {
                let offset = address_offset.into_inner();
                match self.load_memory_value(instruction,offset){
                    Ok(read_records)=>{
                        let addr= read_records.2;
                        if addr % 4 != 0 {
                            return Err(ExecutionError::InvalidMemoryAccess(Opcode::LW, addr));
                        }
                        res=read_records.1.value;
                        res_is_writtten_back_to_stack=true;
                        arg1 =read_records.0.value;
                        arg2 =read_records.1.value;
                        arg1_record=Some(read_records.0);
                        arg2_record=Some(read_records.1);
                    }
                    Err(err) =>return Err(err) ,
                }
            },
            Instruction::F32Load(address_offset) => todo!(),
            Instruction::F64Load(address_offset) => todo!(),
            Instruction::I32Load8S(address_offset) => {
                let offset = address_offset.into_inner();
                match self.load_memory_value(instruction,offset){
                    Ok(read_records)=>{
                        let addr = read_records.2;
                        let value = (read_records.1.value).to_le_bytes()[(addr % 4) as usize];
                        res = ((value as i8) as i32) as u32;
                        res_is_writtten_back_to_stack= true;
                        arg1 =read_records.0.value;
                        arg2 =read_records.1.value;
                        arg1_record=Some(read_records.0);
                        arg2_record=Some(read_records.1);
                    },
                    Err(err) =>return Err(err) ,
                }
              
            },
            Instruction::I32Load8U(address_offset) => {
                let offset = address_offset.into_inner();
                match self.load_memory_value(instruction,offset){
                    Ok(read_records)=>{
                        let addr = read_records.2;
                        let value = (read_records.1.value).to_le_bytes()[(addr % 4) as usize];
                        res =value as u32;
                        res_is_writtten_back_to_stack= true;
                        arg1 =read_records.0.value;
                        arg2 =read_records.1.value;
                        arg1_record=Some(read_records.0);
                        arg2_record=Some(read_records.1);
                    },
                    Err(err) =>return Err(err) ,
               
            }
        }
            Instruction::I32Load16S(address_offset) => {
                let offset = address_offset.into_inner();
                match self.load_memory_value(instruction,offset){
                    Ok(read_records)=>{
                        let addr = read_records.2;
                        let memory_read_value =read_records.1.value;
                        if addr % 2 != 0 {
                            return Err(ExecutionError::InvalidMemoryAccess(Opcode::LH, addr));
                        }
                        let value = match (addr >> 1) % 2 {
                            0 => memory_read_value & 0x0000_FFFF,
                            1 => (memory_read_value & 0xFFFF_0000) >> 16,
                            _ => unreachable!(),
                        };
                        res = ((value as i16) as i32) as u32;
                        res_is_writtten_back_to_stack=true;
                        arg1 =read_records.0.value;
                        arg2 =read_records.1.value;
                        arg1_record=Some(read_records.0);
                        arg2_record=Some(read_records.1);

                    }
                    Err(err) =>return Err(err) ,
                }
               
            },
            Instruction::I32Load16U(address_offset) => {
                let offset = address_offset.into_inner();
                match self.load_memory_value(instruction,offset){
                    Ok(read_records)=>{
                        let addr = read_records.2;
                        let memory_read_value =read_records.1.value;
                        if addr % 2 != 0 {
                            return Err(ExecutionError::InvalidMemoryAccess(Opcode::LHU, addr));
                        }
                        let value = match (addr >> 1) % 2 {
                            0 => memory_read_value & 0x0000_FFFF,
                            1 => (memory_read_value & 0xFFFF_0000) >> 16,
                            _ => unreachable!(),
                        };
                        res = (value as u16)as u32;
                        res_is_writtten_back_to_stack=true;
                        arg1 =read_records.0.value;
                        arg2 =read_records.1.value;
                        arg1_record=Some(read_records.0);
                        arg2_record=Some(read_records.1);

                    }
                    Err(err) =>return Err(err) ,
                }
                
            },
            Instruction::I32Store(address_offset) => {
                (arg1_record,arg2_record)=self.fetch_binary_op_data();
                let value  = arg2_record.unwrap().value;
                
                arg1 = arg1_record.unwrap().value;
                match arg1.checked_add(address_offset.into_inner()){
                    Some(addr)=>{
                        res = value;
                        next_sp = sp-4;
                        res_record = Some(self.write_back_res_to_memory(res, addr, next_sp));
                        res_is_writtten_back_to_stack=false;
                    },
                    None=>{ return Err(ExecutionError::InvalidMemoryAccess(Opcode::SW, 0u32));}
                }
              
            },
            Instruction::I32Store8(address_offset) => {
                (arg1_record,arg2_record)=self.fetch_binary_op_data();
                
                let raw_addr =arg1_record.unwrap().value;
                let full_value  = arg2_record.unwrap().value;
                arg1 = arg1_record.unwrap().value;
               
                match raw_addr.checked_add(address_offset.into_inner()){
                    Some(addr)=>{
                        let memory_value = self.word(align(addr));
                        let value = match addr % 4 {
                            0 => (full_value & 0x0000_00FF) + (memory_value & 0xFFFF_FF00),
                            1 => ((full_value & 0x0000_00FF) << 8) + (memory_value & 0xFFFF_00FF),
                            2 => ((full_value & 0x0000_00FF) << 16) + (memory_value & 0xFF00_FFFF),
                            3 => ((full_value& 0x0000_00FF) << 24) + (memory_value & 0x00FF_FFFF),
                            _ => unreachable!(),
                        };
                        res = value;
                        println!("full:{},memoery:{},res:{}",full_value,memory_value,res);
                        next_sp = sp-4;
                        res_record = Some(self.write_back_res_to_memory(res, addr, next_sp));
                        res_is_writtten_back_to_stack=false;
                    },
                    None=>{ return Err(ExecutionError::InvalidMemoryAccess(Opcode::SB, 0u32));}
                }
            },
            Instruction::I32Store16(address_offset) => {
                (arg1_record,arg2_record)=self.fetch_binary_op_data();
                
                let raw_addr =arg1_record.unwrap().value;
                let full_value  = arg2_record.unwrap().value;
                arg1 = arg1_record.unwrap().value;
               
                match raw_addr.checked_add(address_offset.into_inner()){
                    Some(addr)=>{
                        let memory_value = self.word(align(addr));
                        let value = match addr % 2 {
                            0 => (full_value & 0x0000_FFFF) + (memory_value & 0xFFFF_0000),
                            1 => ((full_value & 0x0000_FFFF) << 16) + (memory_value & 0x0000_FFFF),
                            _ => unreachable!(),
                        };
                        res = value;
                        
                        next_sp = sp-4;
                        res_record = Some(self.write_back_res_to_memory(res, addr, next_sp));
                        res_is_writtten_back_to_stack=false;
                    },
                    None=>{ return Err(ExecutionError::InvalidMemoryAccess(Opcode::SB, 0u32));}
                }
            },
            Instruction::MemorySize => todo!(),
            Instruction::MemoryGrow => todo!(),
            Instruction::MemoryFill => todo!(),
            Instruction::MemoryCopy => todo!(),
            Instruction::MemoryInit(data_segment_idx) => todo!(),
            Instruction::DataDrop(data_segment_idx) => todo!(),
            Instruction::TableSize(table_idx) => todo!(),
            Instruction::TableGrow(table_idx) => todo!(),
            Instruction::TableFill(table_idx) => todo!(),
            Instruction::TableGet(table_idx) => todo!(),
            Instruction::TableSet(table_idx) => todo!(),
            Instruction::TableCopy(table_idx) => todo!(),
            Instruction::TableInit(element_segment_idx) => todo!(),
            Instruction::ElemDrop(element_segment_idx) => todo!(),
            Instruction::RefFunc(func_idx) => todo!(),
            Instruction::I32Const(untyped_value) => todo!(),
            Instruction::ConstRef(const_ref) => todo!(),
            Instruction::I32Eqz => {
                // do not emit alu and event are generated in emit_cpu_dep
                arg1_record = self.fetch_unary_op_data();
                arg1 = arg1_record.unwrap().value;
                res = (arg1 == 0) as u32;
                res_is_writtten_back_to_stack = true;
                println!("arg1_record:{:?} res: {} has_res: {}", arg1_record, res, res_is_writtten_back_to_stack);
            }
            Instruction::I32Eq => {
                // do not emit alu and event are generated in emit_cpu_dep
                (arg1_record, arg2_record) = self.fetch_binary_op_data();
                arg1 = arg1_record.unwrap().value;
                arg2 = arg2_record.unwrap().value;
                res = (arg1 == arg2) as u32;
                next_sp = sp - 4;
                res_is_writtten_back_to_stack = true;
            }
            Instruction::I32Ne => {
                // do not emit alu and event are generated in emit_cpu_dep
                (arg1_record, arg2_record) = self.fetch_binary_op_data();
                arg1 = arg1_record.unwrap().value;
                arg2 = arg2_record.unwrap().value;
                res = (arg1 != arg2) as u32;
                next_sp = sp - 4;
                res_is_writtten_back_to_stack = true;
            }
            Instruction::I32LtS => {
                (arg1_record, arg2_record) = self.fetch_binary_op_data();
                arg1 = arg1_record.unwrap().value;
                arg2 = arg2_record.unwrap().value;
                let arg1_signed = arg1 as i32;
                let arg2_singed = arg2 as i32;
                res = (arg1_signed < arg2_singed) as u32;
                next_sp = sp - 4;
                res_is_writtten_back_to_stack = true;
                self.emit_alu(clk, Opcode::SLT, res, arg1, arg2, lookup_id);
            }
            Instruction::I32LtU => {
                (arg1_record, arg2_record) = self.fetch_binary_op_data();
                arg1 = arg1_record.unwrap().value;
                arg2 = arg2_record.unwrap().value;
                res = (arg1 < arg2) as u32;
                next_sp = sp - 4;
                res_is_writtten_back_to_stack = true;
                self.emit_alu(clk, Opcode::SLTU, res, arg1, arg2, lookup_id);
            }
            Instruction::I32GtS => {
                // do not emit alu and event are generated in emit_cpu_dep
                (arg1_record, arg2_record) = self.fetch_binary_op_data();
                arg1 = arg1_record.unwrap().value;
                arg2 = arg2_record.unwrap().value;
                let arg1_signed = arg1 as i32;
                let arg2_singed = arg2 as i32;
                res = (arg1_signed > arg2_singed) as u32;
                next_sp = sp - 4;
                res_is_writtten_back_to_stack = true;
            }
            Instruction::I32GtU => {
                // do not emit alu and event are generated in emit_cpu_dep
                (arg1_record, arg2_record) = self.fetch_binary_op_data();
                arg1 = arg1_record.unwrap().value;
                arg2 = arg2_record.unwrap().value;
                res = (arg1 > arg2) as u32;
                next_sp = sp - 4;
                res_is_writtten_back_to_stack = true;
            }
            Instruction::I32LeS => {
                // do not emit alu and event are generated in emit_cpu_dep
                (arg1_record, arg2_record) = self.fetch_binary_op_data();
                arg1 = arg1_record.unwrap().value;
                arg2 = arg2_record.unwrap().value;
                let arg1_signed = arg1 as i32;
                let arg2_singed = arg2 as i32;
                res = (arg1_signed <= arg2_singed) as u32;
                next_sp = sp - 4;
                res_is_writtten_back_to_stack = true;
            }
            Instruction::I32LeU => {
                // do not emit alu and event are generated in emit_cpu_dep
                (arg1_record, arg2_record) = self.fetch_binary_op_data();
                arg1 = arg1_record.unwrap().value;
                arg2 = arg2_record.unwrap().value;
                res = (arg1 <= arg2) as u32;
                next_sp = sp - 4;
                res_is_writtten_back_to_stack = true;
            }
            Instruction::I32GeS => {
                // do not emit alu and event are generated in emit_cpu_dep
                (arg1_record, arg2_record) = self.fetch_binary_op_data();
                arg1 = arg1_record.unwrap().value;
                arg2 = arg2_record.unwrap().value;
                let arg1_signed = arg1 as i32;
                let arg2_singed = arg2 as i32;
                res = (arg1_signed >= arg2_singed) as u32;
                next_sp = sp - 4;
                res_is_writtten_back_to_stack = true;
            }
            Instruction::I32GeU => {
                // do not emit alu and event are generated in emit_cpu_dep
                (arg1_record, arg2_record) = self.fetch_binary_op_data();
                arg1 = arg1_record.unwrap().value;
                arg2 = arg2_record.unwrap().value;
                res = (arg1 >= arg2) as u32;
                next_sp = sp - 4;
                res_is_writtten_back_to_stack = true;
            }
            Instruction::I32Clz => todo!(),
            Instruction::I32Ctz => todo!(),
            Instruction::I32Popcnt => todo!(),
            Instruction::I32Add => {
                (arg1_record, arg2_record) = self.fetch_binary_op_data();
                arg1 = arg1_record.unwrap().value;
                arg2 = arg2_record.unwrap().value;
                res = arg1.wrapping_add(arg2);
                next_sp = sp - 4;
                res_is_writtten_back_to_stack = true;
                self.emit_alu(clk, Opcode::ADD, res, arg1, arg2, lookup_id);
            }
            Instruction::I32Sub => {
                (arg1_record, arg2_record) = self.fetch_binary_op_data();
                arg1 = arg1_record.unwrap().value;
                arg2 = arg2_record.unwrap().value;
                res = arg1.wrapping_sub(arg2);
                next_sp = sp - 4;
                res_is_writtten_back_to_stack = true;
                self.emit_alu(clk, Opcode::SUB, res, arg1, arg2, lookup_id);
            }
            Instruction::I32Mul => {
                (arg1_record, arg2_record) = self.fetch_binary_op_data();
                arg1 = arg1_record.unwrap().value;
                arg2 = arg2_record.unwrap().value;
                res = arg1.wrapping_mul(arg2);
                next_sp = sp - 4;
                res_is_writtten_back_to_stack = true;
                self.emit_alu(clk, Opcode::MUL, res, arg1, arg2, lookup_id);
            }
            Instruction::I32DivS => {
                (arg1_record, arg2_record) = self.fetch_binary_op_data();
                arg1 = arg1_record.unwrap().value;
                arg2 = arg2_record.unwrap().value;
                let signed_arg1 = arg1 as i32;
                let signed_arg2 = arg2 as i32;
                res = (signed_arg1.wrapping_div(signed_arg2)) as u32;
                next_sp = sp - 4;
                res_is_writtten_back_to_stack = true;
                self.emit_alu(clk, Opcode::DIV, res, arg1, arg2, lookup_id);
            }
            Instruction::I32DivU => {
                (arg1_record, arg2_record) = self.fetch_binary_op_data();
                arg1 = arg1_record.unwrap().value;
                arg2 = arg2_record.unwrap().value;
                res = arg1.wrapping_div(arg2);
                next_sp = sp - 4;
                res_is_writtten_back_to_stack = true;
                self.emit_alu(clk, Opcode::DIVU, res, arg1, arg2, lookup_id);
            }
            Instruction::I32RemS => {
                (arg1_record, arg2_record) = self.fetch_binary_op_data();
                arg1 = arg1_record.unwrap().value;
                arg2 = arg2_record.unwrap().value;
                let signed_arg1 = arg1 as i32;
                let signed_arg2 = arg2 as i32;
                res = (signed_arg1.wrapping_rem(signed_arg2)) as u32;
                next_sp = sp - 4;
                res_is_writtten_back_to_stack = true;
                self.emit_alu(clk, Opcode::REM, res, arg1, arg2, lookup_id);
            }
            Instruction::I32RemU => {
                (arg1_record, arg2_record) = self.fetch_binary_op_data();
                arg1 = arg1_record.unwrap().value;
                arg2 = arg2_record.unwrap().value;
                res = arg1.wrapping_rem(arg2);
                next_sp = sp - 4;
                res_is_writtten_back_to_stack = true;
                self.emit_alu(clk, Opcode::REMU, res, arg1, arg2, lookup_id);
            }
            Instruction::I32And => {
                (arg1_record, arg2_record) = self.fetch_binary_op_data();
                arg1 = arg1_record.unwrap().value;
                arg2 = arg2_record.unwrap().value;
                res = arg1 & arg2;
                next_sp = sp - 4;
                res_is_writtten_back_to_stack = true;
                self.emit_alu(clk, Opcode::AND, res, arg1, arg2, lookup_id);
            }
            Instruction::I32Or => {
                (arg1_record, arg2_record) = self.fetch_binary_op_data();
                arg1 = arg1_record.unwrap().value;
                arg2 = arg2_record.unwrap().value;
                res = arg1 | arg2;
                next_sp = sp - 4;
                res_is_writtten_back_to_stack = true;
                self.emit_alu(clk, Opcode::OR, res, arg1, arg2, lookup_id);
            }
            Instruction::I32Xor => {
                (arg1_record, arg2_record) = self.fetch_binary_op_data();
                arg1 = arg1_record.unwrap().value;
                arg2 = arg2_record.unwrap().value;
                res = arg1 ^ arg2;
                next_sp = sp - 4;
                res_is_writtten_back_to_stack = true;
                self.emit_alu(clk, Opcode::XOR, res, arg1, arg2, lookup_id);
            }

            Instruction::I32Shl => {
                (arg1_record, arg2_record) = self.fetch_binary_op_data();
                arg1 = arg1_record.unwrap().value;
                arg2 = arg2_record.unwrap().value;
                res = arg1.wrapping_shl(arg2);
                next_sp = sp - 4;
                res_is_writtten_back_to_stack = true;
                self.emit_alu(clk, Opcode::SLL, res, arg1, arg2, lookup_id);
            }
            Instruction::I32ShrS => {
                (arg1_record, arg2_record) = self.fetch_binary_op_data();
                arg1 = arg1_record.unwrap().value;
                arg2 = arg2_record.unwrap().value;
                res = (arg1 as i32).wrapping_shr(arg2) as u32; //TODO check
                next_sp = sp - 4;
                res_is_writtten_back_to_stack = true;
                self.emit_alu(clk, Opcode::SRA, res, arg1, arg2, lookup_id);
            }
            Instruction::I32ShrU => {
                (arg1_record, arg2_record) = self.fetch_binary_op_data();
                arg1 = arg1_record.unwrap().value;
                arg2 = arg2_record.unwrap().value;
                res = arg1.wrapping_shr(arg2); //Todo check
                next_sp = sp - 4;
                res_is_writtten_back_to_stack = true;
                self.emit_alu(clk, Opcode::SRL, res, arg1, arg2, lookup_id);
            }
            Instruction::I32Rotl => todo!(),
            Instruction::I32Rotr => todo!(),

            Instruction::I32WrapI64 => todo!(),
            Instruction::I32TruncF32S => todo!(),
            Instruction::I32TruncF32U => todo!(),
            Instruction::I32TruncF64S => todo!(),
            Instruction::I32TruncF64U => todo!(),
            Instruction::I64ExtendI32S => todo!(),
            Instruction::I64ExtendI32U => todo!(),
            Instruction::I64TruncF32S => todo!(),
            Instruction::I64TruncF32U => todo!(),
            Instruction::I64TruncF64S => todo!(),
            Instruction::I64TruncF64U => todo!(),
            Instruction::F32ConvertI32S => todo!(),
            Instruction::F32ConvertI32U => todo!(),
            Instruction::F32ConvertI64S => todo!(),
            Instruction::F32ConvertI64U => todo!(),
            Instruction::F32DemoteF64 => todo!(),
            Instruction::F64ConvertI32S => todo!(),
            Instruction::F64ConvertI32U => todo!(),
            Instruction::F64ConvertI64S => todo!(),
            Instruction::F64ConvertI64U => todo!(),
            Instruction::F64PromoteF32 => todo!(),
            Instruction::I32Extend8S => todo!(),
            Instruction::I32Extend16S => todo!(),
            Instruction::I64Extend8S => todo!(),
            Instruction::I64Extend16S => todo!(),
            Instruction::I64Extend32S => todo!(),
            Instruction::I32TruncSatF32S => todo!(),
            Instruction::I32TruncSatF32U => todo!(),
            Instruction::I32TruncSatF64S => todo!(),
            Instruction::I32TruncSatF64U => todo!(),
            Instruction::I64TruncSatF32S => todo!(),
            Instruction::I64TruncSatF32U => todo!(),
            Instruction::I64TruncSatF64S => todo!(),
            Instruction::I64TruncSatF64U => todo!(),
            _ => todo!(),
        }


        if res_is_writtten_back_to_stack{
            res_record=Some(self.write_back_res_to_stack(res, next_sp));
        }

        // Update the program counter.
        self.state.pc = next_pc;

        // Update the clk to the next cycle.
        self.state.clk += 4;

        // Emit the CPU event for this cycle.
        if self.executor_mode == ExecutorMode::Trace {
            self.emit_cpu(
                self.shard(),
                clk,
                pc,
                next_pc,
                sp,
                next_sp,
                *instruction,
                arg1,
                arg2,
                res,
                arg1_record,
                arg2_record,
                res_record,
                exit_code,
                lookup_id,
                syscall_lookup_id,
            );
        };
        Ok(())
    }

    /// Executes one cycle of the program, returning whether the program has finished.
    #[inline]
    #[allow(clippy::too_many_lines)]
    fn execute_cycle(&mut self) -> Result<bool, ExecutionError> {
        // Fetch the instruction at the current program counter.
        let instruction = self.fetch();

        // Log the current state of the runtime.
        #[cfg(debug_assertions)]
        self.log(&instruction);

        // Execute the instruction.
        self.execute_instruction(&instruction)?;

        // Increment the clock.
        self.state.global_clk += 1;

        if !self.unconstrained {
            // If there's not enough cycles left for another instruction, move to the next shard.
            let cpu_exit = self.max_syscall_cycles + self.state.clk >= self.shard_size;

            // Every N cycles, check if there exists at least one shape that fits.
            //
            // If we're close to not fitting, early stop the shard to ensure we don't OOM.
            let mut shape_match_found = true;
            if self.state.global_clk % 16 == 0 {
                let addsub_count = (self.report.event_counts[Opcode::ADD]
                    + self.report.event_counts[Opcode::SUB])
                    as usize;
                let mul_count = (self.report.event_counts[Opcode::MUL]
                    + self.report.event_counts[Opcode::MULH]
                    + self.report.event_counts[Opcode::MULHU]
                    + self.report.event_counts[Opcode::MULHSU])
                    as usize;
                let bitwise_count = (self.report.event_counts[Opcode::XOR]
                    + self.report.event_counts[Opcode::OR]
                    + self.report.event_counts[Opcode::AND])
                    as usize;
                let shift_left_count = self.report.event_counts[Opcode::SLL] as usize;
                let shift_right_count = (self.report.event_counts[Opcode::SRL]
                    + self.report.event_counts[Opcode::SRA])
                    as usize;
                let divrem_count = (self.report.event_counts[Opcode::DIV]
                    + self.report.event_counts[Opcode::DIVU]
                    + self.report.event_counts[Opcode::REM]
                    + self.report.event_counts[Opcode::REMU])
                    as usize;
                let lt_count = (self.report.event_counts[Opcode::SLT]
                    + self.report.event_counts[Opcode::SLTU])
                    as usize;

                if let Some(maximal_shapes) = &self.maximal_shapes {
                    shape_match_found = false;

                    for shape in maximal_shapes.iter() {
                        let addsub_threshold = 1 << shape["AddSub"];
                        if addsub_count > addsub_threshold {
                            continue;
                        }
                        let addsub_distance = addsub_threshold - addsub_count;

                        let mul_threshold = 1 << shape["Mul"];
                        if mul_count > mul_threshold {
                            continue;
                        }
                        let mul_distance = mul_threshold - mul_count;

                        let bitwise_threshold = 1 << shape["Bitwise"];
                        if bitwise_count > bitwise_threshold {
                            continue;
                        }
                        let bitwise_distance = bitwise_threshold - bitwise_count;

                        let shift_left_threshold = 1 << shape["ShiftLeft"];
                        if shift_left_count > shift_left_threshold {
                            continue;
                        }
                        let shift_left_distance = shift_left_threshold - shift_left_count;

                        let shift_right_threshold = 1 << shape["ShiftRight"];
                        if shift_right_count > shift_right_threshold {
                            continue;
                        }
                        let shift_right_distance = shift_right_threshold - shift_right_count;

                        let divrem_threshold = 1 << shape["DivRem"];
                        if divrem_count > divrem_threshold {
                            continue;
                        }
                        let divrem_distance = divrem_threshold - divrem_count;

                        let lt_threshold = 1 << shape["Lt"];
                        if lt_count > lt_threshold {
                            continue;
                        }
                        let lt_distance = lt_threshold - lt_count;

                        let l_infinity = vec![
                            addsub_distance,
                            mul_distance,
                            bitwise_distance,
                            shift_left_distance,
                            shift_right_distance,
                            divrem_distance,
                            lt_distance,
                        ]
                        .into_iter()
                        .min()
                        .unwrap();

                        if l_infinity >= 32 {
                            shape_match_found = true;
                            break;
                        }
                    }

                    if !shape_match_found {
                        log::warn!(
                            "stopping shard early due to no shapes fitting: \
                            nb_cycles={}, \
                            addsub_count={}, \
                            mul_count={}, \
                            bitwise_count={}, \
                            shift_left_count={}, \
                            shift_right_count={}, \
                            divrem_count={}, \
                            lt_count={}",
                            self.state.clk / 4,
                            log2_ceil_usize(addsub_count),
                            log2_ceil_usize(mul_count),
                            log2_ceil_usize(bitwise_count),
                            log2_ceil_usize(shift_left_count),
                            log2_ceil_usize(shift_right_count),
                            log2_ceil_usize(divrem_count),
                            log2_ceil_usize(lt_count),
                        );
                    }
                }
            }

            if cpu_exit || !shape_match_found {
                self.state.current_shard += 1;
                self.state.clk = 0;
                self.report.event_counts = Box::default();
                self.bump_record();
            }
        }

        // If the cycle limit is exceeded, return an error.
        if let Some(max_cycles) = self.max_cycles {
            if self.state.global_clk >= max_cycles {
                return Err(ExecutionError::ExceededCycleLimit(max_cycles));
            }
        }

        let done = self.state.pc == 0
            || self.state.pc.wrapping_sub(self.program.pc_base)
                >= (self.program.instructions.len() * 4) as u32;
        if done && self.unconstrained {
            log::error!("program ended in unconstrained mode at clk {}", self.state.global_clk);
            return Err(ExecutionError::EndInUnconstrained());
        }
        Ok(done)
    }

    /// Bump the record.
    pub fn bump_record(&mut self) {
        // Copy all of the existing local memory accesses to the record's local_memory_access vec.
        for (_, event) in self.local_memory_access.drain() {
            self.record.cpu_local_memory_access.push(event);
        }

        let removed_record =
            std::mem::replace(&mut self.record, ExecutionRecord::new(self.program.clone()));
        let public_values = removed_record.public_values;
        self.record.public_values = public_values;
        self.records.push(removed_record);
    }

    /// Execute up to `self.shard_batch_size` cycles, returning the events emitted and whether the
    /// program ended.
    ///
    /// # Errors
    ///
    /// This function will return an error if the program execution fails.
    pub fn execute_record(&mut self) -> Result<(Vec<ExecutionRecord>, bool), ExecutionError> {
        self.executor_mode = ExecutorMode::Trace;
        self.print_report = true;
        let done = self.execute()?;
        Ok((std::mem::take(&mut self.records), done))
    }

    /// Execute up to `self.shard_batch_size` cycles, returning the checkpoint from before execution
    /// and whether the program ended.
    ///
    /// # Errors
    ///
    /// This function will return an error if the program execution fails.
    pub fn execute_state(&mut self) -> Result<(ExecutionState, bool), ExecutionError> {
        self.memory_checkpoint.clear();
        self.executor_mode = ExecutorMode::Checkpoint;

        // Clone self.state without memory and uninitialized_memory in it so it's faster.
        let memory = std::mem::take(&mut self.state.memory);
        let uninitialized_memory = std::mem::take(&mut self.state.uninitialized_memory);
        let mut checkpoint = tracing::info_span!("clone").in_scope(|| self.state.clone());
        self.state.memory = memory;
        self.state.uninitialized_memory = uninitialized_memory;

        let done = tracing::info_span!("execute").in_scope(|| self.execute())?;
        // Create a checkpoint using `memory_checkpoint`. Just include all memory if `done` since we
        // need it all for MemoryFinalize.
        tracing::info_span!("create memory checkpoint").in_scope(|| {
            let memory_checkpoint = std::mem::take(&mut self.memory_checkpoint);
            let uninitialized_memory_checkpoint =
                std::mem::take(&mut self.uninitialized_memory_checkpoint);
            if done {
                // If we're done, we need to include all memory. But we need to reset any modified
                // memory to as it was before the execution.
                checkpoint.memory.clone_from(&self.state.memory);
                memory_checkpoint.into_iter().for_each(|(addr, record)| {
                    if let Some(record) = record {
                        checkpoint.memory.insert(addr, record);
                    } else {
                        checkpoint.memory.remove(addr);
                    }
                });
                checkpoint.uninitialized_memory = self.state.uninitialized_memory.clone();
                // Remove memory that was written to in this batch.
                for (addr, is_old) in uninitialized_memory_checkpoint {
                    if !is_old {
                        checkpoint.uninitialized_memory.remove(addr);
                    }
                }
            } else {
                checkpoint.memory = memory_checkpoint
                    .into_iter()
                    .filter_map(|(addr, record)| record.map(|record| (addr, record)))
                    .collect();
                checkpoint.uninitialized_memory = uninitialized_memory_checkpoint
                    .into_iter()
                    .filter(|&(_, has_value)| has_value)
                    .map(|(addr, _)| (addr, *self.state.uninitialized_memory.get(addr).unwrap()))
                    .collect();
            }
        });
        Ok((checkpoint, done))
    }

    fn initialize(&mut self) {
        self.state.clk = 0;

        tracing::debug!("loading memory image");
        for (&addr, value) in &self.program.memory_image {
            self.state.memory.insert(addr, MemoryRecord { value: *value, shard: 0, timestamp: 0 });
        }
    }

    /// Executes the program without tracing and without emitting events.
    ///
    /// # Errors
    ///
    /// This function will return an error if the program execution fails.
    pub fn run_fast(&mut self) -> Result<(), ExecutionError> {
        self.executor_mode = ExecutorMode::Simple;
        self.print_report = true;
        while !self.execute()? {}
        Ok(())
    }

    /// Executes the program and prints the execution report.
    ///
    /// # Errors
    ///
    /// This function will return an error if the program execution fails.
    pub fn run(&mut self) -> Result<(), ExecutionError> {
        self.executor_mode = ExecutorMode::Trace;
        self.print_report = true;
        while !self.execute()? {}
        Ok(())
    }

    /// Executes up to `self.shard_batch_size` cycles of the program, returning whether the program
    /// has finished.
    pub fn execute(&mut self) -> Result<bool, ExecutionError> {
        // Get the program.
        let program = self.program.clone();

        // Get the current shard.
        let start_shard = self.state.current_shard;

        // If it's the first cycle, initialize the program.
        if self.state.global_clk == 0 {
            self.initialize();
        }

        // Loop until we've executed `self.shard_batch_size` shards if `self.shard_batch_size` is
        // set.
        let mut done = false;
        let mut current_shard = self.state.current_shard;
        let mut num_shards_executed = 0;
        loop {
            if self.execute_cycle()? {
                done = true;
                break;
            }

            if self.shard_batch_size > 0 && current_shard != self.state.current_shard {
                num_shards_executed += 1;
                current_shard = self.state.current_shard;
                if num_shards_executed == self.shard_batch_size {
                    break;
                }
            }
        }

        // Get the final public values.
        let public_values = self.record.public_values;
        println!("done?{}", done);
        if done {
            self.postprocess();

            // Push the remaining execution record with memory initialize & finalize events.
            self.bump_record();
        }

        // Push the remaining execution record, if there are any CPU events.
        if !self.record.cpu_events.is_empty() {
            self.bump_record();
        }

        // Set the global public values for all shards.
        let mut last_next_pc = 0;
        let mut last_exit_code = 0;
        for (i, record) in self.records.iter_mut().enumerate() {
            record.program = program.clone();
            record.public_values = public_values;
            record.public_values.committed_value_digest = public_values.committed_value_digest;
            record.public_values.deferred_proofs_digest = public_values.deferred_proofs_digest;
            record.public_values.execution_shard = start_shard + i as u32;
            if record.cpu_events.is_empty() {
                record.public_values.start_pc = last_next_pc;
                record.public_values.next_pc = last_next_pc;
                record.public_values.exit_code = last_exit_code;
            } else {
                record.public_values.start_pc = record.cpu_events[0].pc;
                record.public_values.next_pc = record.cpu_events.last().unwrap().next_pc;
                record.public_values.exit_code = record.cpu_events.last().unwrap().exit_code;
                last_next_pc = record.public_values.next_pc;
                last_exit_code = record.public_values.exit_code;
            }
        }

        Ok(done)
    }

    fn postprocess(&mut self) {
        // Flush remaining stdout/stderr
        for (fd, buf) in &self.io_buf {
            if !buf.is_empty() {
                match fd {
                    1 => {
                        println!("stdout: {buf}");
                    }
                    2 => {
                        println!("stderr: {buf}");
                    }
                    _ => {}
                }
            }
        }

        // Flush trace buf
        if let Some(ref mut buf) = self.trace_buf {
            buf.flush().unwrap();
        }

        // Ensure that all proofs and input bytes were read, otherwise warn the user.
        // if self.state.proof_stream_ptr != self.state.proof_stream.len() {
        //     panic!(
        //         "Not all proofs were read. Proving will fail during recursion. Did you pass too
        // many proofs in or forget to call verify_sp1_proof?"     );
        // }
        if self.state.input_stream_ptr != self.state.input_stream.len() {
            tracing::warn!("Not all input bytes were read.");
        }

        if self.executor_mode == ExecutorMode::Trace {
            // SECTION: Set up all MemoryInitializeFinalizeEvents needed for memory argument.
            let memory_finalize_events = &mut self.record.global_memory_finalize_events;

            // We handle the addr = 0 case separately, as we constrain it to be 0 in the first row
            // of the memory finalize table so it must be first in the array of events.
            let addr_0_record = self.state.memory.get(0);

            let addr_0_final_record = match addr_0_record {
                Some(record) => record,
                None => &MemoryRecord { value: 0, shard: 0, timestamp: 0 },
            };

            println!("add_0_record{:?}", addr_0_record);
            println!("add_0_final_record{:?}", addr_0_final_record);
            memory_finalize_events
                .push(MemoryInitializeFinalizeEvent::finalize_from_record(0, addr_0_final_record));

            let memory_initialize_events = &mut self.record.global_memory_initialize_events;
            let addr_0_initialize_event = MemoryInitializeFinalizeEvent::initialize(0, 0, true);
            memory_initialize_events.push(addr_0_initialize_event);

            // Count the number of touched memory addresses manually, since `PagedMemory` doesn't
            // already know its length.
            self.report.touched_memory_addresses = 0;
            for addr in self.state.memory.keys() {
                self.report.touched_memory_addresses += 1;
                if addr == 0 {
                    // Handled above.
                    continue;
                }

                // Program memory is initialized in the MemoryProgram chip and doesn't require any
                // events, so we only send init events for other memory addresses.
                if !self.record.program.memory_image.contains_key(&addr) {
                    let initial_value = self.state.uninitialized_memory.get(addr).unwrap_or(&0);
                    memory_initialize_events.push(MemoryInitializeFinalizeEvent::initialize(
                        addr,
                        *initial_value,
                        true,
                    ));
                }

                let record = *self.state.memory.get(addr).unwrap();
                memory_finalize_events
                    .push(MemoryInitializeFinalizeEvent::finalize_from_record(addr, &record));
            }
        }
    }

    fn get_syscall(&mut self, code: SyscallCode) -> Option<&Arc<dyn Syscall>> {
        self.syscall_map.get(&code)
    }

    #[inline]
    #[cfg(debug_assertions)]
    fn log(&mut self, _: &Instruction) {
        // Write the current program counter to the trace buffer for the cycle tracer.
        if let Some(ref mut buf) = self.trace_buf {
            if !self.unconstrained {
                buf.write_all(&u32::to_be_bytes(self.state.pc)).unwrap();
            }
        }

        if !self.unconstrained && self.state.global_clk % 10_000_000 == 0 {
            log::info!("clk = {} pc = 0x{:x?}", self.state.global_clk, self.state.pc);
        }
    }
}

impl Default for ExecutorMode {
    fn default() -> Self {
        Self::Simple
    }
}

// TODO: FIX
/// Aligns an address to the nearest word below or equal to it.
#[must_use]
pub const fn align(addr: u32) -> u32 {
    addr - addr % 4
}

fn log2_ceil_usize(n: usize) -> usize {
    (usize::BITS - n.saturating_sub(1).leading_zeros()) as usize
}
#[cfg(test)]
mod tests {
    use crate::{Executor, Program, SP_START};
    use hashbrown::HashMap;
    use rwasm::engine::bytecode::{BranchOffset, Instruction};
    use sp1_stark::SP1CoreOpts;

    #[test]
    fn test_add() {
        let sp_value: u32 = SP_START;
        let x_value: u32 = 4;
        let y_value: u32 = 32;

        let mut mem = HashMap::new();
        mem.insert(sp_value, x_value);
        mem.insert(sp_value - 4, y_value);

        let instructions = vec![
            Instruction::I32Add, // 32 + 4 = 36
        ];

        let program = Program {
            instructions,
            pc_base: 0,
            pc_start: 0,
            memory_image: mem,
            preprocessed_shape: None,
        };
        let mut runtime = Executor::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.state.memory.get(runtime.state.sp).unwrap().value, 36);

        println!("initial sp_value {} and last state.sp {}", sp_value, runtime.state.sp);
    }
    #[test]
    fn test_sub() {
        let sp_value: u32 = SP_START;
        let x_value: u32 = 32;
        let y_value: u32 = 4;

        let mut mem = HashMap::new();
        mem.insert(sp_value, x_value);
        mem.insert(sp_value - 4, y_value);

        let instructions = vec![
            Instruction::I32Sub, // 32 - 4 = 28
        ];

        let program = Program {
            instructions,
            pc_base: 0,
            pc_start: 0,
            memory_image: mem,
            preprocessed_shape: None,
        };
        let mut runtime = Executor::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.state.memory.get(runtime.state.sp).unwrap().value, 28);
    }
    #[test]
    fn test_xor() {
        let sp_value: u32 = SP_START;
        let x_value: u32 = 5;
        let y_value: u32 = 37;

        let mut mem = HashMap::new();
        mem.insert(sp_value, x_value);
        mem.insert(sp_value - 4, y_value);

        let instructions = vec![
            Instruction::I32Xor, // 5 xor 37 = 32
        ];

        let program = Program {
            instructions,
            pc_base: 0,
            pc_start: 0,
            memory_image: mem,
            preprocessed_shape: None,
        };
        let mut runtime = Executor::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.state.memory.get(runtime.state.sp).unwrap().value, 32);
    }
    #[test]
    fn test_or() {
        let sp_value: u32 = SP_START;
        let x_value: u32 = 5;
        let y_value: u32 = 37;

        let mut mem = HashMap::new();
        mem.insert(sp_value, x_value);
        mem.insert(sp_value - 4, y_value);

        let instructions = vec![
            Instruction::I32Or, // 5 or 37 = 32
        ];

        let program = Program {
            instructions,
            pc_base: 0,
            pc_start: 0,
            memory_image: mem,
            preprocessed_shape: None,
        };
        let mut runtime = Executor::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.state.memory.get(runtime.state.sp).unwrap().value, 37);
    }
    #[test]
    fn test_and() {
        let sp_value: u32 = SP_START;
        let x_value: u32 = 5;
        let y_value: u32 = 37;

        let mut mem = HashMap::new();
        mem.insert(sp_value, x_value);
        mem.insert(sp_value - 4, y_value);

        let instructions = vec![
            Instruction::I32And, // 5 and 37 = 32
        ];

        let program = Program {
            instructions,
            pc_base: 0,
            pc_start: 0,
            memory_image: mem,
            preprocessed_shape: None,
        };
        let mut runtime = Executor::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.state.memory.get(runtime.state.sp).unwrap().value, 5);
    }
    #[test]
    fn test_addi_negative() {
        let sp_value: u32 = SP_START;
        let x_value: u32 = 4;
        let y_value: u32 = 0xFFFF_FFFF;
        let z_value: u32 = 5;

        let mut mem = HashMap::new();
        mem.insert(sp_value, x_value);
        mem.insert(sp_value - 4, y_value);
        mem.insert(sp_value - 8, z_value);

        let instructions = vec![Instruction::I32Add, Instruction::I32Add];

        let program = Program {
            instructions,
            pc_base: 0,
            pc_start: 0,
            memory_image: mem,
            preprocessed_shape: None,
        };
        let mut runtime = Executor::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.state.memory.get(runtime.state.sp).unwrap().value, 5 - 1 + 4);
    }

    #[test]
    fn test_ori() {
        let sp_value: u32 = SP_START;
        let x_value: u32 = 5;
        let y_value: u32 = 37;
        let z_value: u32 = 42;

        let mut mem = HashMap::new();
        mem.insert(sp_value, x_value);
        mem.insert(sp_value - 4, y_value);
        mem.insert(sp_value - 8, z_value);

        let instructions = vec![
            Instruction::I32Or, // 5 or 37 = 37
            Instruction::I32Or, // 37 or 42  = 47
        ];

        let program = Program {
            instructions,
            pc_base: 0,
            pc_start: 0,
            memory_image: mem,
            preprocessed_shape: None,
        };
        let mut runtime = Executor::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.state.memory.get(runtime.state.sp).unwrap().value, 47);
    }
    #[test]
    fn test_andi() {
        let sp_value: u32 = SP_START;
        let x_value: u32 = 5;
        let y_value: u32 = 37;
        let z_value: u32 = 4;

        let mut mem = HashMap::new();
        mem.insert(sp_value, x_value);
        mem.insert(sp_value - 4, y_value);
        mem.insert(sp_value - 8, z_value);

        let instructions = vec![
            Instruction::I32And, // 5 and 37 = 32
            Instruction::I32And, // 5 and 4  = 4
        ];

        let program = Program {
            instructions,
            pc_base: 0,
            pc_start: 0,
            memory_image: mem,
            preprocessed_shape: None,
        };
        let mut runtime = Executor::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.state.memory.get(runtime.state.sp).unwrap().value, 4);
    }
    #[test]
    fn test_mul() {
        let sp_value: u32 = SP_START;
        let x_value: u32 = 5;
        let y_value: u32 = 32;

        let mut mem = HashMap::new();
        mem.insert(sp_value, x_value);
        mem.insert(sp_value - 4, y_value);

        let instructions = vec![
            Instruction::I32Mul, // 5 * 32 = 160
        ];

        let program = Program {
            instructions,
            pc_base: 0,
            pc_start: 0,
            memory_image: mem,
            preprocessed_shape: None,
        };
        let mut runtime = Executor::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.state.memory.get(runtime.state.sp).unwrap().value, x_value * y_value);
    }
    #[test]
    fn test_eq() {
        let sp_value: u32 = SP_START;
        let x_value: u32 = 32;
        let y_value: u32 = 32;

        let mut mem = HashMap::new();
        mem.insert(sp_value, x_value);
        mem.insert(sp_value - 4, y_value);

        let instructions = vec![
            Instruction::I32Eq, // check whether x_value is equal y_value
        ];

        let program = Program {
            instructions,
            pc_base: 0,
            pc_start: 0,
            memory_image: mem,
            preprocessed_shape: None,
        };
        let mut runtime = Executor::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.state.memory.get(runtime.state.sp).unwrap().value, 1);
    }
    #[test]
    fn test_ne() {
        let sp_value: u32 = SP_START;
        let x_value: u32 = 32;
        let y_value: u32 = 32;
        let z_value: u32 = 1;

        let mut mem = HashMap::new();
        mem.insert(sp_value, x_value);
        mem.insert(sp_value - 4, y_value);
        mem.insert(sp_value - 8, z_value);

        let instructions = vec![
            Instruction::I32Ne, // check whether x_value is not equal y_value
            Instruction::I32Ne,
        ];

        let program = Program {
            instructions,
            pc_base: 0,
            pc_start: 0,
            memory_image: mem,
            preprocessed_shape: None,
        };
        let mut runtime = Executor::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.state.memory.get(runtime.state.sp).unwrap().value, 1);
    }
    #[test]
    fn test_eqz() {
        let sp_value: u32 = SP_START;
        let x_value: u32 = 32;

        let mut mem = HashMap::new();
        mem.insert(sp_value, x_value);

        let instructions = vec![
            Instruction::I32Eqz, // check whether x_value is zero
        ];

        let program = Program {
            instructions,
            pc_base: 0,
            pc_start: 0,
            memory_image: mem,
            preprocessed_shape: None,
        };
        let mut runtime = Executor::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.state.memory.get(runtime.state.sp).unwrap().value, 0);
    }
    #[test]
    fn test_lts_ltu() {
        let sp_value: u32 = SP_START;
        let x_value: u32 = 3222;
        let y_value: u32 = 233;
        let z_value: u32 = 32;
        let mut mem = HashMap::new();
        mem.insert(sp_value, x_value);
        mem.insert(sp_value - 4, y_value);
        mem.insert(sp_value - 8, z_value);

        let instructions = vec![
            Instruction::I32LtS, // check whether signed x_value is less than signed y_value
            Instruction::I32LtU, // check whether unsigned x_value is less than unsigned y_value
        ];

        let program = Program {
            instructions,
            pc_base: 0,
            pc_start: 0,
            memory_image: mem,
            preprocessed_shape: None,
        };
        let mut runtime = Executor::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.state.memory.get(runtime.state.sp).unwrap().value, 1);
    }
    #[test]
    fn test_gts_gtu() {
        let sp_value: u32 = SP_START;
        let x_value: u32 = 3222;
        let y_value: u32 = 233;
        let z_value: u32 = 32;
        let mut mem = HashMap::new();
        mem.insert(sp_value, x_value);
        mem.insert(sp_value - 4, y_value);
        mem.insert(sp_value - 8, z_value);

        let instructions = vec![
            Instruction::I32GtS, // check whether signed x_value is greater than signed y_value
            Instruction::I32GtU, // check whether unsigned x_value is greater than unsigned y_value
        ];

        let program = Program {
            instructions,
            pc_base: 0,
            pc_start: 0,
            memory_image: mem,
            preprocessed_shape: None,
        };
        let mut runtime = Executor::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.state.memory.get(runtime.state.sp).unwrap().value, 0);
    }
    #[test]
    fn test_ges_geu() {
        let sp_value: u32 = SP_START;
        let x_value: u32 = 321;
        let y_value: u32 = 233;
        let z_value: u32 = 1;
        let mut mem = HashMap::new();
        mem.insert(sp_value, x_value);
        mem.insert(sp_value - 4, y_value);
        mem.insert(sp_value - 8, z_value);

        let instructions = vec![
            Instruction::I32GeS, // check whether signed x_value is greater than or equal to signed y_value
            Instruction::I32GeU, // check whether unsigned x_value is greater than or equal to unsigned y_value
        ];

        let program = Program {
            instructions,
            pc_base: 0,
            pc_start: 0,
            memory_image: mem,
            preprocessed_shape: None,
        };
        let mut runtime = Executor::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.state.memory.get(runtime.state.sp).unwrap().value, 1);
    }
    #[test]
    fn test_les_leu() {
        let sp_value: u32 = SP_START;
        let x_value: u32 = 321;
        let y_value: u32 = 233;
        let z_value: u32 = 0;
        let mut mem = HashMap::new();
        mem.insert(sp_value, x_value);
        mem.insert(sp_value - 4, y_value);
        mem.insert(sp_value - 8, z_value);

        let instructions = vec![
            Instruction::I32LeS, // check whether signed x_value is less than or equal to signed y_value
            Instruction::I32LeU, // check whether unsigned x_value is less than or equal to unsigned y_value
        ];

        let program = Program {
            instructions,
            pc_base: 0,
            pc_start: 0,
            memory_image: mem,
            preprocessed_shape: None,
        };
        let mut runtime = Executor::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.state.memory.get(runtime.state.sp).unwrap().value, 1);
    }
    #[test]
    fn test_divs_divu() {
        let sp_value: u32 = SP_START;
        let x_value: u32 = 320;
        let y_value: u32 = 10;
        let z_value: u32 = 2;
        let mut mem = HashMap::new();
        mem.insert(sp_value, x_value);
        mem.insert(sp_value - 4, y_value);
        mem.insert(sp_value - 8, z_value);

        let instructions = vec![
            Instruction::I32DivS, // divide x_value by y_value and return quotient (x and y are signed)
            Instruction::I32DivU, // divide x_value by y_value and return quotient
        ];

        let program = Program {
            instructions,
            pc_base: 0,
            pc_start: 0,
            memory_image: mem,
            preprocessed_shape: None,
        };
        let mut runtime = Executor::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(
            runtime.state.memory.get(runtime.state.sp).unwrap().value,
            x_value / y_value / z_value
        );
    }
    #[test]
    fn test_rems_remu() {
        let sp_value: u32 = SP_START;
        let x_value: u32 = 320;
        let y_value: u32 = 13;
        let z_value: u32 = 5;
        let mut mem = HashMap::new();
        mem.insert(sp_value, x_value);
        mem.insert(sp_value - 4, y_value);
        mem.insert(sp_value - 8, z_value);

        let instructions = vec![
            Instruction::I32RemS, // divide x_value by y_value and return remainder (x and y are signed)
            Instruction::I32RemU, // divide x_value by y_value and return remainder
        ];

        let program = Program {
            instructions,
            pc_base: 0,
            pc_start: 0,
            memory_image: mem,
            preprocessed_shape: None,
        };
        let mut runtime = Executor::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(
            runtime.state.memory.get(runtime.state.sp).unwrap().value,
            (x_value % y_value) % z_value
        );
    }
    #[test]
    fn test_shl() {
        let sp_value: u32 = SP_START;
        let x_value: u32 = 2;
        let y_value: u32 = 2;
        let z_value: u32 = 3;
        let mut mem = HashMap::new();
        mem.insert(sp_value, x_value);
        mem.insert(sp_value - 4, y_value);
        mem.insert(sp_value - 8, z_value);

        let instructions = vec![
            Instruction::I32Shl, // x_value is shifted left by y_value
            Instruction::I32Shl,
        ];

        let program = Program {
            instructions,
            pc_base: 0,
            pc_start: 0,
            memory_image: mem,
            preprocessed_shape: None,
        };
        let mut runtime = Executor::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(
            runtime.state.memory.get(runtime.state.sp).unwrap().value,
            x_value << (y_value + z_value)
        );
    }
    #[test]
    fn test_shr_shru() {
        let sp_value: u32 = SP_START;
        let x_value: u32 = 256;
        let y_value: u32 = 2;
        let z_value: u32 = 3;
        let mut mem = HashMap::new();
        mem.insert(sp_value, x_value);
        mem.insert(sp_value - 4, y_value);
        mem.insert(sp_value - 8, z_value);

        let instructions = vec![
            Instruction::I32ShrS, // x_value is shifted right by y_value
            Instruction::I32ShrU, //
        ];

        let program = Program {
            instructions,
            pc_base: 0,
            pc_start: 0,
            memory_image: mem,
            preprocessed_shape: None,
        };
        let mut runtime = Executor::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(
            runtime.state.memory.get(runtime.state.sp).unwrap().value,
            x_value >> (y_value + z_value)
        );
    }

    fn simple_instruction_test(opcode: Instruction, expected: u32, a: u32, b: u32) {
        let sp_value: u32 = SP_START;
        let x_value: u32 = a;
        let y_value: u32 = b;
        let mut mem = HashMap::new();
        mem.insert(sp_value, x_value);
        mem.insert(sp_value - 4, y_value);
        let instructions = vec![opcode];
        let program = Program {
            instructions,
            pc_base: 0,
            pc_start: 0,
            memory_image: mem,
            preprocessed_shape: None,
        };
        let mut runtime = Executor::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.state.memory.get(runtime.state.sp).unwrap().value, expected);
    }
    #[test]
    #[allow(clippy::unreadable_literal)]
    fn multiplication_tests() {
        simple_instruction_test(Instruction::I32Mul, 0x00001200, 0x00007e00, 0xb6db6db7);
        simple_instruction_test(Instruction::I32Mul, 0x00001240, 0x00007fc0, 0xb6db6db7);
        simple_instruction_test(Instruction::I32Mul, 0x00000000, 0x00000000, 0x00000000);
        simple_instruction_test(Instruction::I32Mul, 0x00000001, 0x00000001, 0x00000001);
        simple_instruction_test(Instruction::I32Mul, 0x00000015, 0x00000003, 0x00000007);
        simple_instruction_test(Instruction::I32Mul, 0x00000000, 0x00000000, 0xffff8000);
        simple_instruction_test(Instruction::I32Mul, 0x00000000, 0x80000000, 0x00000000);
        simple_instruction_test(Instruction::I32Mul, 0x00000000, 0x80000000, 0xffff8000);
        simple_instruction_test(Instruction::I32Mul, 0x0000ff7f, 0xaaaaaaab, 0x0002fe7d);
        simple_instruction_test(Instruction::I32Mul, 0x0000ff7f, 0x0002fe7d, 0xaaaaaaab);
        simple_instruction_test(Instruction::I32Mul, 0x00000000, 0xff000000, 0xff000000);
        simple_instruction_test(Instruction::I32Mul, 0x00000001, 0xffffffff, 0xffffffff);
        simple_instruction_test(Instruction::I32Mul, 0xffffffff, 0xffffffff, 0x00000001);
        simple_instruction_test(Instruction::I32Mul, 0xffffffff, 0x00000001, 0xffffffff);
    }
    #[test]
    fn division_tests() {
        simple_instruction_test(Instruction::I32DivU, 3, 20, 6);
        simple_instruction_test(Instruction::I32DivU, 715_827_879, u32::MAX - 20 + 1, 6);
        simple_instruction_test(Instruction::I32DivU, 0, 20, u32::MAX - 6 + 1);
        simple_instruction_test(Instruction::I32DivU, 0, u32::MAX - 20 + 1, u32::MAX - 6 + 1);

        simple_instruction_test(Instruction::I32DivU, 1 << 31, 1 << 31, 1);
        simple_instruction_test(Instruction::I32DivU, 0, 1 << 31, u32::MAX - 1 + 1);

        //  simple_instruction_test(Instruction::I32DivU, u32::MAX, 1 << 31, 0);
        // simple_instruction_test(Instruction::I32DivU, u32::MAX, 1, 0);
        //  simple_instruction_test(Instruction::I32DivU, u32::MAX, 0, 0);

        simple_instruction_test(Instruction::I32DivS, 3, 18, 6);
        simple_instruction_test(Instruction::I32DivS, neg(6), neg(24), 4);
        simple_instruction_test(Instruction::I32DivS, neg(2), 16, neg(8));
        //   simple_instruction_test(Instruction::I32DivS, neg(1), 0, 0);

        // Overflow cases
        simple_instruction_test(Instruction::I32DivS, 1 << 31, 1 << 31, neg(1));
        simple_instruction_test(Instruction::I32RemS, 0, 1 << 31, neg(1));
    }
    #[test]
    fn remainder_tests() {
        simple_instruction_test(Instruction::I32RemS, 7, 16, 9);
        simple_instruction_test(Instruction::I32RemS, neg(4), neg(22), 6);
        simple_instruction_test(Instruction::I32RemS, 1, 25, neg(3));
        simple_instruction_test(Instruction::I32RemS, neg(2), neg(22), neg(4));
        simple_instruction_test(Instruction::I32RemS, 0, 873, 1);
        simple_instruction_test(Instruction::I32RemS, 0, 873, neg(1));
        //simple_instruction_test(Instruction::I32RemS, 5, 5, 0);
        //simple_instruction_test(Instruction::I32RemS, neg(5), neg(5), 0);
        //simple_instruction_test(Instruction::I32RemS, 0, 0, 0);

        simple_instruction_test(Instruction::I32RemU, 4, 18, 7);
        simple_instruction_test(Instruction::I32RemU, 6, neg(20), 11);
        simple_instruction_test(Instruction::I32RemU, 23, 23, neg(6));
        simple_instruction_test(Instruction::I32RemU, neg(21), neg(21), neg(11));
        // simple_instruction_test(Instruction::I32RemU, 5, 5, 0);
        // simple_instruction_test(Instruction::I32RemU, neg(1), neg(1), 0);
        // simple_instruction_test(Instruction::I32RemU, 0, 0, 0);
    }
    #[test]
    #[allow(clippy::unreadable_literal)]
    fn shift_tests() {
        simple_instruction_test(Instruction::I32Shl, 0x00000001, 0x00000001, 0);
        simple_instruction_test(Instruction::I32Shl, 0x00000002, 0x00000001, 1);
        simple_instruction_test(Instruction::I32Shl, 0x00000080, 0x00000001, 7);
        simple_instruction_test(Instruction::I32Shl, 0x00004000, 0x00000001, 14);
        simple_instruction_test(Instruction::I32Shl, 0x80000000, 0x00000001, 31);
        simple_instruction_test(Instruction::I32Shl, 0xffffffff, 0xffffffff, 0);
        simple_instruction_test(Instruction::I32Shl, 0xfffffffe, 0xffffffff, 1);
        simple_instruction_test(Instruction::I32Shl, 0xffffff80, 0xffffffff, 7);
        simple_instruction_test(Instruction::I32Shl, 0xffffc000, 0xffffffff, 14);
        simple_instruction_test(Instruction::I32Shl, 0x80000000, 0xffffffff, 31);
        simple_instruction_test(Instruction::I32Shl, 0x21212121, 0x21212121, 0);
        simple_instruction_test(Instruction::I32Shl, 0x42424242, 0x21212121, 1);
        simple_instruction_test(Instruction::I32Shl, 0x90909080, 0x21212121, 7);
        simple_instruction_test(Instruction::I32Shl, 0x48484000, 0x21212121, 14);
        simple_instruction_test(Instruction::I32Shl, 0x80000000, 0x21212121, 31);
        simple_instruction_test(Instruction::I32Shl, 0x21212121, 0x21212121, 0xffffffe0);
        simple_instruction_test(Instruction::I32Shl, 0x42424242, 0x21212121, 0xffffffe1);
        simple_instruction_test(Instruction::I32Shl, 0x90909080, 0x21212121, 0xffffffe7);
        simple_instruction_test(Instruction::I32Shl, 0x48484000, 0x21212121, 0xffffffee);
        simple_instruction_test(Instruction::I32Shl, 0x00000000, 0x21212120, 0xffffffff);

        simple_instruction_test(Instruction::I32ShrU, 0xffff8000, 0xffff8000, 0);
        simple_instruction_test(Instruction::I32ShrU, 0x7fffc000, 0xffff8000, 1);
        simple_instruction_test(Instruction::I32ShrU, 0x01ffff00, 0xffff8000, 7);
        simple_instruction_test(Instruction::I32ShrU, 0x0003fffe, 0xffff8000, 14);
        simple_instruction_test(Instruction::I32ShrU, 0x0001ffff, 0xffff8001, 15);
        simple_instruction_test(Instruction::I32ShrU, 0xffffffff, 0xffffffff, 0);
        simple_instruction_test(Instruction::I32ShrU, 0x7fffffff, 0xffffffff, 1);
        simple_instruction_test(Instruction::I32ShrU, 0x01ffffff, 0xffffffff, 7);
        simple_instruction_test(Instruction::I32ShrU, 0x0003ffff, 0xffffffff, 14);
        simple_instruction_test(Instruction::I32ShrU, 0x00000001, 0xffffffff, 31);
        simple_instruction_test(Instruction::I32ShrU, 0x21212121, 0x21212121, 0);
        simple_instruction_test(Instruction::I32ShrU, 0x10909090, 0x21212121, 1);
        simple_instruction_test(Instruction::I32ShrU, 0x00424242, 0x21212121, 7);
        simple_instruction_test(Instruction::I32ShrU, 0x00008484, 0x21212121, 14);
        simple_instruction_test(Instruction::I32ShrU, 0x00000000, 0x21212121, 31);
        simple_instruction_test(Instruction::I32ShrU, 0x21212121, 0x21212121, 0xffffffe0);
        simple_instruction_test(Instruction::I32ShrU, 0x10909090, 0x21212121, 0xffffffe1);
        simple_instruction_test(Instruction::I32ShrU, 0x00424242, 0x21212121, 0xffffffe7);
        simple_instruction_test(Instruction::I32ShrU, 0x00008484, 0x21212121, 0xffffffee);
        simple_instruction_test(Instruction::I32ShrU, 0x00000000, 0x21212121, 0xffffffff);

        simple_instruction_test(Instruction::I32ShrS, 0x00000000, 0x00000000, 0);
        simple_instruction_test(Instruction::I32ShrS, 0xc0000000, 0x80000000, 1);
        simple_instruction_test(Instruction::I32ShrS, 0xff000000, 0x80000000, 7);
        simple_instruction_test(Instruction::I32ShrS, 0xfffe0000, 0x80000000, 14);
        simple_instruction_test(Instruction::I32ShrS, 0xffffffff, 0x80000001, 31);
        simple_instruction_test(Instruction::I32ShrS, 0x7fffffff, 0x7fffffff, 0);
        simple_instruction_test(Instruction::I32ShrS, 0x3fffffff, 0x7fffffff, 1);
        simple_instruction_test(Instruction::I32ShrS, 0x00ffffff, 0x7fffffff, 7);
        simple_instruction_test(Instruction::I32ShrS, 0x0001ffff, 0x7fffffff, 14);
        simple_instruction_test(Instruction::I32ShrS, 0x00000000, 0x7fffffff, 31);
        simple_instruction_test(Instruction::I32ShrS, 0x81818181, 0x81818181, 0);
        simple_instruction_test(Instruction::I32ShrS, 0xc0c0c0c0, 0x81818181, 1);
        simple_instruction_test(Instruction::I32ShrS, 0xff030303, 0x81818181, 7);
        simple_instruction_test(Instruction::I32ShrS, 0xfffe0606, 0x81818181, 14);
        simple_instruction_test(Instruction::I32ShrS, 0xffffffff, 0x81818181, 31);
    }
    fn neg(a: u32) -> u32 {
        u32::MAX - a + 1
    }

    #[test]
    fn test_load32() {
        let sp_value: u32 = SP_START;
        let x_value: u32 = 5;
        let addr :u32 = 0x10000;
        let mut mem = HashMap::new();
        mem.insert(sp_value, addr);
        mem.insert(addr, x_value);

        let instructions = vec![
            Instruction::I32Load(0.into()), // 5 and 37 = 32
        ];

        let program = Program {
            instructions,
            pc_base: 0,
            pc_start: 0,
            memory_image: mem,
            preprocessed_shape: None,
        };
        let mut runtime = Executor::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.state.memory.get(runtime.state.sp).unwrap().value, x_value);
    }

    #[test]
    fn test_load16u() {
        let sp_value: u32 = SP_START;
        let x_value: u32 = 0xFFFF_0005;
      
        let y_value: u32 = 0x0000_1234;
        let addr :u32 = 0x10000;
        let mut mem = HashMap::new();
        mem.insert(sp_value, addr);
        mem.insert(sp_value-4, addr);
        mem.insert(addr, x_value);

        let instructions = vec![
            Instruction::I32Load16U(0.into()), // 5 and 37 = 32
        ];

        let program = Program {
            instructions,
            pc_base: 0,
            pc_start: 0,
            memory_image: mem,
            preprocessed_shape: None,
        };
        let mut runtime = Executor::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.state.memory.get(runtime.state.sp).unwrap().value, x_value&0x0000_FFFF);
    }

    #[test]
    fn test_load16s() {
        let sp_value: u32 = SP_START;
        let x_value:u32 = (-5i16) as u16 as u32 &0xFFFF_0000;
        let addr :u32 = 0x10000;
        let mut mem = HashMap::new();
        mem.insert(sp_value, addr);
        mem.insert(sp_value-4, addr);
        mem.insert(addr, x_value);

        let instructions = vec![
            Instruction::I32Load16S(0.into()), // 5 and 37 = 32
        ];

        let program = Program {
            instructions,
            pc_base: 0,
            pc_start: 0,
            memory_image: mem,
            preprocessed_shape: None,
        };
        let mut runtime = Executor::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.state.memory.get(runtime.state.sp).unwrap().value, x_value&0x0000_FFFF);
    }

    #[test]
    fn test_load8u() {
        let sp_value: u32 = SP_START;
        let x_value: u32 = 0xFFFF_05FF;
        let addr :u32 = 0x10000;
        let mut mem = HashMap::new();
        mem.insert(sp_value, addr);
        mem.insert(sp_value-4, addr);
        mem.insert(addr, x_value);

        let instructions = vec![
            Instruction::I32Load8U(0.into()), // 5 and 37 = 32
        ];

        let program = Program {
            instructions,
            pc_base: 0,
            pc_start: 0,
            memory_image: mem,
            preprocessed_shape: None,
        };
        let mut runtime = Executor::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.state.memory.get(runtime.state.sp).unwrap().value, x_value&0x0000_FF05>>8);
    }

    #[test]
    fn test_load8s() {
        let sp_value: u32 = SP_START;
        let x_value:u32 = (((-5i8) as u8 as u32)<<8)&0xFFFF_00FF;
        let addr :u32 = 0x10000;
        let mut mem = HashMap::new();
        mem.insert(sp_value, addr);
        mem.insert(sp_value-4, addr);
        mem.insert(addr, x_value);

        let instructions = vec![
            Instruction::I32Load8S(1.into()), // 5 and 37 = 32
        ];

        let program = Program {
            instructions,
            pc_base: 0,
            pc_start: 0,
            memory_image: mem,
            preprocessed_shape: None,
        };
        let mut runtime = Executor::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.state.memory.get(runtime.state.sp).unwrap().value, x_value&0x0000_FF00);
    }


    #[test]
    fn test_store() {
        let sp_value: u32 = SP_START;
        let x_value:u32 =5;
        let addr :u32 = 0x10000;
        let mut mem = HashMap::new();
        mem.insert(sp_value, addr);
        mem.insert(sp_value-4, x_value);
      

        let instructions = vec![
            Instruction::I32Store(0.into()), // 5 and 37 = 32
        ];

        let program = Program {
            instructions,
            pc_base: 0,
            pc_start: 0,
            memory_image: mem,
            preprocessed_shape: None,
        };
        let mut runtime = Executor::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.state.memory.get(addr).unwrap().value, x_value);
    }

    #[test]
    fn test_store16() {
        let sp_value: u32 = SP_START;
        let x_value: u32 = 0xFFFF_0005;
        let addr :u32 = 0x10000;
        let mut mem = HashMap::new();
        mem.insert(sp_value, addr);
        mem.insert(sp_value-4, x_value);
      

        let instructions = vec![
            Instruction::I32Store16(0.into()), // 5 and 37 = 32
        ];

        let program = Program {
            instructions,
            pc_base: 0,
            pc_start: 0,
            memory_image: mem,
            preprocessed_shape: None,
        };
        let mut runtime = Executor::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.state.memory.get(addr).unwrap().value, x_value&0x0000_FFFF);
    }

    #[test]
    fn test_store8() {
        let sp_value: u32 = SP_START;
        let x_value: u32 = 0xFFFF_0005;
        let addr :u32 = 0x10000;
        let mut mem = HashMap::new();
        mem.insert(sp_value, addr);
        mem.insert(sp_value-4, x_value);
      

        let instructions = vec![
            Instruction::I32Store8(1.into()), // 5 and 37 = 32
        ];

        let program = Program {
            instructions,
            pc_base: 0,
            pc_start: 0,
            memory_image: mem,
            preprocessed_shape: None,
        };
        let mut runtime = Executor::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.state.memory.get(addr).unwrap().value, (x_value&0x0000_00FF)<<8);
    }
    #[test]
    fn test_br(){
        let sp_value: u32 = SP_START;
        let x_value: u32 = 0xFFFF_0005;
       
        let mut mem = HashMap::new();
        
        mem.insert(sp_value, x_value);
      

       
        let sp_value: u32 = SP_START;
        let x_value: u32 = 0x1;
        let addr :u32 = 0x10000;
        let mut mem = HashMap::new();
        mem.insert(sp_value, x_value);
        mem.insert(sp_value-4, x_value);
        mem.insert(sp_value-8, x_value);
        mem.insert(sp_value-12, x_value);

        let instructions = vec![
            Instruction::Br(2.into()),
            Instruction::I32Shl,
            Instruction::I32Shl,
        ];

        let program = Program {
            instructions,
            pc_base: 0,
            pc_start: 0,
            memory_image: mem,
            preprocessed_shape: None,
        };
        let mut runtime = Executor::new(program, SP1CoreOpts::default());
        
        runtime.run().unwrap();
        assert_eq!(runtime.state.memory.get(runtime.state.sp).unwrap().value, 2);
        
    }
    #[test]
    fn build_elf_branching(){
        /*
        let t0 = Register::X5;
            let syscall_id = self.register(t0);
            c = self.rr(Register::X11, MemoryAccessPosition::C);
            b = self.rr(Register::X10, MemoryAccessPosition::B);
            let syscall = SyscallCode::from_u32(syscall_id);
        */

        let sp_value: u32 = SP_START;
        let x_value: u32 = 0x0;
        let x_2_value: u32 = 0x10008;
        let x_3_value: u32 = 0x1000C;
        


        let mut mem = HashMap::new();
        mem.insert(sp_value, x_value);
        mem.insert(sp_value-4, x_2_value);
        mem.insert(sp_value-8, x_3_value);
        
    
        println!("{:?}", mem);
        let instructions = vec![
            Instruction::Br(20.into()),
            Instruction::I32Add,
            Instruction::I32Add,
            Instruction::I32Add,
            Instruction::BrIfNez(12.into()),
            Instruction::I32Add,
            Instruction::BrIfNez(BranchOffset::from(-8i32)),
            
        ];

    let program = Program {
        instructions,
        pc_base: 1, //If it's a shard with "CPU", then `start_pc` should never equal zero
        pc_start: 1, //If it's a shard with "CPU", then `start_pc` should never equal zero
        memory_image: mem,
        preprocessed_shape: None,
    };
    //  memory_image: BTreeMap::new() };
    let mut runtime = Executor::new(program, SP1CoreOpts::default());
    runtime.run().unwrap();
        assert_eq!(runtime.state.sp, 2);
    runtime.run().unwrap();
        assert_eq!(runtime.state.memory.get(runtime.state.sp).unwrap().value, 2);
    }

}
