use hashbrown::HashMap;
use itertools::Itertools;
use rwasm::{engine::{bytecode::Instruction, DropKeep}, rwasm::InstructionExtra};
use sp1_primitives::consts::WORD_SIZE;
use sp1_rwasm_executor::{
    events::{ByteLookupEvent, ByteRecord, CpuEvent, LookupId, MemoryRecordEnum},
    syscalls::SyscallCode,
    ByteOpcode::{self, U16Range},
    CoreShape, ExecutionRecord, Opcode, Program,
    Register::X0,
};
use sp1_stark::{air::MachineAir, Word};
use std::{array, borrow::BorrowMut};

use p3_field::{PrimeField, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::{
    IntoParallelRefMutIterator, ParallelBridge, ParallelIterator, ParallelSlice,
};
use tracing::instrument;

use super::{
    columns::{CPU_COL_MAP, NUM_CPU_COLS},
    CpuChip,
};
use crate::{cpu::columns::CpuCols, memory::MemoryCols, utils::zeroed_f_vec};

impl<F: PrimeField32> MachineAir<F> for CpuChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        "CPU".to_string()
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        _: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        let mut values = zeroed_f_vec(input.cpu_events.len() * NUM_CPU_COLS);

        let chunk_size = std::cmp::max(input.cpu_events.len() / num_cpus::get(), 1);
        values.chunks_mut(chunk_size * NUM_CPU_COLS).enumerate().par_bridge().for_each(
            |(i, rows)| {
                rows.chunks_mut(NUM_CPU_COLS).enumerate().for_each(|(j, row)| {
                    let idx = i * chunk_size + j;
                    let cols: &mut CpuCols<F> = row.borrow_mut();
                    let mut byte_lookup_events = Vec::new();
                    self.event_to_row(
                        &input.cpu_events[idx],
                        &input.nonce_lookup,
                        cols,
                        &mut byte_lookup_events,
                    );
                });
            },
        );

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(values, NUM_CPU_COLS);

        // Pad the trace to a power of two.
        Self::pad_to_power_of_two::<F>(self, &input.shape, &mut trace.values);

        trace
    }

    #[instrument(name = "generate cpu dependencies", level = "debug", skip_all)]
    fn generate_dependencies(&self, input: &ExecutionRecord, output: &mut ExecutionRecord) {
        // Generate the trace rows for each event.
        let chunk_size = std::cmp::max(input.cpu_events.len() / num_cpus::get(), 1);

        let blu_events: Vec<_> = input
            .cpu_events
            .par_chunks(chunk_size)
            .map(|ops: &[CpuEvent]| {
                // The blu map stores shard -> map(byte lookup event -> multiplicity).
                let mut blu: HashMap<u32, HashMap<ByteLookupEvent, usize>> = HashMap::new();
                ops.iter().for_each(|op| {
                    let mut row = [F::zero(); NUM_CPU_COLS];
                    let cols: &mut CpuCols<F> = row.as_mut_slice().borrow_mut();
                    self.event_to_row::<F>(op, &HashMap::new(), cols, &mut blu);
                });
                blu
            })
            .collect::<Vec<_>>();

        output.add_sharded_byte_lookup_events(blu_events.iter().collect_vec());
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            shard.contains_cpu()
        }
    }
}

impl CpuChip {
    /// Create a row from an event.
    fn event_to_row<F: PrimeField32>(
        &self,
        event: &CpuEvent,
        nonce_lookup: &HashMap<LookupId, u32>,
        cols: &mut CpuCols<F>,
        blu_events: &mut impl ByteRecord,
    ) {
        // Populate shard and clk columns.
        self.populate_shard_clk(cols, event, blu_events);

        // Populate the nonce.
        cols.nonce = F::from_canonical_u32(
            nonce_lookup.get(&event.alu_lookup_id).copied().unwrap_or_default(),
        );

        // Populate basic fields.
        cols.pc = F::from_canonical_u32(event.pc);
        cols.next_pc = F::from_canonical_u32(event.next_pc);
        cols.sp = F::from_canonical_u32(event.sp);
        cols.next_sp = F::from_canonical_u32(event.next_sp);
        cols.instruction.populate(event.instruction);
        cols.selectors.populate(event.instruction);
        cols.op_arg1=event.arg1.into();
        cols.op_arg2=event.arg2.into();
        cols.res=event.res.into();
        println!("evnet ins:{}",event.instruction);
        // Populate memory accesses for a, b, and c.
        if let Some(record) = event.arg1_record {
            println!("arg_1 record:{:?}",record);
            cols.op_arg1_access.populate(record, blu_events);
        }

        if matches!(
            event.instruction,
            Instruction::I32Load(_)
                | Instruction::I32Load16S(_)
                | Instruction::I32Load16U(_)
                | Instruction::I32Load8S(_)
                | Instruction::I32Load8U(_)
                | Instruction::I32Store(_)
                | Instruction::I32Store16(_)
                | Instruction::I32Store8(_)
        ){
            let memory_columns = cols.opcode_specific_columns.memory_mut();
            if matches!( event.instruction,
                Instruction::I32Load(_)
                    | Instruction::I32Load16S(_)
                    | Instruction::I32Load16U(_)
                    | Instruction::I32Load8S(_)
                    | Instruction::I32Load8U(_)){
                        if let Some(record) = event.arg2_record {
                            println!("arg_2 record:{:?}",record);
                            memory_columns.memory_access.populate(MemoryRecordEnum::Read(record), blu_events)
                        }
                        if let Some(record) = event.res_record {
                            println!("arg_res record:{:?}",record);
                            cols.op_res_access.populate(record, blu_events);
                        }
                    } else{
                        if let Some(record) = event.arg2_record {
                            println!("populate store");
                            println!("arg_2 record:{:?}",record);
                            cols.op_arg2_access.populate(record, blu_events);
                        }
                        if let Some(record) = event.res_record {
                            println!("arg_res record:{:?}",record);
                            memory_columns.memory_access.populate(MemoryRecordEnum::Write(record), blu_events)
                        }
                    }

        } else{
            if let Some(record) = event.arg2_record {
                println!("arg_2 record:{:?}",record);
                cols.op_arg2_access.populate(record, blu_events);
            }
            if let Some(record) = event.res_record {
                println!("arg_res record:{:?}",record);
                cols.op_res_access.populate(record, blu_events);
            }
        }



          // Populate memory accesses for reading from memory.
        
       

        // // Populate memory, branch, jump, and auipc specific fields.
        self.populate_alu(cols, event,nonce_lookup);
        self.populate_memory(cols, event, blu_events, nonce_lookup);
        self.populate_branch(cols, event, nonce_lookup);
        self.populate_funccall(cols, event);
        // self.populate_jump(cols, event, nonce_lookup);
        // self.populate_auipc(cols, event, nonce_lookup);
        // let is_halt = self.populate_ecall(cols, event, nonce_lookup);

        cols.is_sequential_instr = F::from_bool(
            !event.instruction.is_branch_instruction() && !event.instruction.is_jump_instruction()
            &&!event.instruction.is_call_instruction() // && !is_halt,
        );

        // Assert that the instruction is not a no-op.
        cols.is_real = F::one();
    }

    /// Populates the shard and clk related rows.
    fn populate_shard_clk<F: PrimeField>(
        &self,
        cols: &mut CpuCols<F>,
        event: &CpuEvent,
        blu_events: &mut impl ByteRecord,
    ) {
        cols.shard = F::from_canonical_u32(event.shard);
        cols.clk = F::from_canonical_u32(event.clk);

        let clk_16bit_limb = (event.clk & 0xffff) as u16;
        let clk_8bit_limb = ((event.clk >> 16) & 0xff) as u8;
        cols.clk_16bit_limb = F::from_canonical_u16(clk_16bit_limb);
        cols.clk_8bit_limb = F::from_canonical_u8(clk_8bit_limb);

        blu_events.add_byte_lookup_event(ByteLookupEvent::new(
            event.shard,
            U16Range,
            event.shard as u16,
            0,
            0,
            0,
        ));
        blu_events.add_byte_lookup_event(ByteLookupEvent::new(
            event.shard,
            U16Range,
            clk_16bit_limb,
            0,
            0,
            0,
        ));
        blu_events.add_byte_lookup_event(ByteLookupEvent::new(
            event.shard,
            ByteOpcode::U8Range,
            0,
            0,
            0,
            clk_8bit_limb as u8,
        ));
    }

    /// Populates columns related to memory.
    fn populate_memory<F: PrimeField>(
        &self,
        cols: &mut CpuCols<F>,
        event: &CpuEvent,
        blu_events: &mut impl ByteRecord,
        nonce_lookup: &HashMap<LookupId, u32>,
    ) {
        if !matches!(
            event.instruction,
            Instruction::I32Load(_)
                | Instruction::I32Load16S(_)
                | Instruction::I32Load16U(_)
                | Instruction::I32Load8S(_)
                | Instruction::I32Load8U(_)
                | Instruction::I32Store(_)
                | Instruction::I32Store16(_)
                | Instruction::I32Store8(_)
        ) {
            return;
        }
      
        let offset = event.instruction.aux_value().unwrap().into();
        println!("ins:{:?}",event.instruction);
        println!("memoryoffset:{}",offset);
        // Populate addr_word and addr_aligned columns.
        let memory_columns = cols.opcode_specific_columns.memory_mut();
        let memory_addr = event.arg1.wrapping_add(offset);
        println!("memor_addr:{}",memory_addr);
        let aligned_addr = memory_addr - memory_addr % WORD_SIZE as u32;
        memory_columns.addr_word = memory_addr.into();
        memory_columns.addr_word_range_checker.populate(memory_addr);
        memory_columns.addr_aligned = F::from_canonical_u32(aligned_addr);

        // Populate the aa_least_sig_byte_decomp columns.
        assert!(aligned_addr % 4 == 0);
        let aligned_addr_ls_byte = (aligned_addr & 0x000000FF) as u8;
        let bits: [bool; 8] = array::from_fn(|i| aligned_addr_ls_byte & (1 << i) != 0);
        memory_columns.aa_least_sig_byte_decomp = array::from_fn(|i| F::from_bool(bits[i + 2]));
        memory_columns.addr_word_nonce = F::from_canonical_u32(
            nonce_lookup.get(&event.memory_add_lookup_id).copied().unwrap_or_default(),
        );

        // Populate memory offsets.
        let addr_offset = (memory_addr % WORD_SIZE as u32) as u8;
        memory_columns.addr_offset = F::from_canonical_u8(addr_offset);
        memory_columns.offset_is_one = F::from_bool(addr_offset == 1);
        memory_columns.offset_is_two = F::from_bool(addr_offset == 2);
        memory_columns.offset_is_three = F::from_bool(addr_offset == 3);

        // If it is a load instruction, set the unsigned_mem_val column.
        let mem_value = event.res;
        if matches!(
            event.instruction,
            Instruction::I32Load(_)
            | Instruction::I32Load16S(_)
            | Instruction::I32Load16U(_)
            | Instruction::I32Load8S(_)
            | Instruction::I32Load8U(_)
        ) {
            match event.instruction {
                | Instruction::I32Load8S(_)
            | Instruction::I32Load8U(_)=> {
                    cols.unsigned_mem_val =
                        (mem_value.to_le_bytes()[addr_offset as usize] as u32).into();
                }
                | Instruction::I32Load16S(_)
            | Instruction::I32Load16U(_) => {
                    let value = match (addr_offset >> 1) % 2 {
                        0 => mem_value & 0x0000FFFF,
                        1 => (mem_value & 0xFFFF0000) >> 16,
                        _ => unreachable!(),
                    };
                    cols.unsigned_mem_val = value.into();
                }
                Instruction::I32Load(_) => {
                    cols.unsigned_mem_val = mem_value.into();
                }
                _ => unreachable!(),
            }

            // For the signed load instructions, we need to check if the loaded value is negative.
            if matches!(event.instruction,  Instruction::I32Load16S(_) |  Instruction::I32Load8S(_)) {
                let most_sig_mem_value_byte = if matches!(event.instruction, Instruction::I32Load8S(_)) {
                    cols.unsigned_mem_val.to_u32().to_le_bytes()[0]
                } else {
                    cols.unsigned_mem_val.to_u32().to_le_bytes()[1]
                };

                for i in (0..8).rev() {
                    memory_columns.most_sig_byte_decomp[i] =
                        F::from_canonical_u8(most_sig_mem_value_byte >> i & 0x01);
                }
                if memory_columns.most_sig_byte_decomp[7] == F::one() {
                   
                    cols.unsigned_mem_val_nonce = F::from_canonical_u32(
                        nonce_lookup.get(&event.memory_sub_lookup_id).copied().unwrap_or_default(),
                    );
                }
            }
           
        }
      

        // Add event to byte lookup for byte range checking each byte in the memory addr
        let addr_bytes = memory_addr.to_le_bytes();
        for byte_pair in addr_bytes.chunks_exact(2) {
            blu_events.add_byte_lookup_event(ByteLookupEvent {
                shard: event.shard,
                opcode: ByteOpcode::U8Range,
                a1: 0,
                a2: 0,
                b: byte_pair[0],
                c: byte_pair[1],
            });
        }
    }

    /// Populates columns related to branching.
    fn populate_branch<F: PrimeField>(
        &self,
        cols: &mut CpuCols<F>,
        event: &CpuEvent,
        nonce_lookup: &HashMap<LookupId, u32>,
    ) {
        if event.instruction.is_branch_instruction() {
            let branch_columns = cols.opcode_specific_columns.branch_mut();

            let a_eq_zero = event.arg1 == 0;

       
            let a_gt_zero = event.arg1>0;

           
           let offset = match event.instruction{
                Instruction::Br(offset)=>offset.to_i32(),
                Instruction::BrIfEqz(offset)=>offset.to_i32(),
                Instruction::BrIfNez(offset)=>offset.to_i32(),
                _=>0,
           };
            println!("ins:{},offset:{}",event.instruction,offset);
            branch_columns.a_gt_b_nonce = F::from_canonical_u32(
                nonce_lookup.get(&event.branch_gt_lookup_id).copied().unwrap_or_default(),
            );

            branch_columns.a_eq_zero = F::from_bool(a_eq_zero);
           
            branch_columns.a_gt_zero = F::from_bool(a_gt_zero);

            let branching = match event.instruction {
                Instruction::Br(_) => true,
                Instruction::BrIfNez(_) => !a_eq_zero,
                Instruction::BrIfEqz(_) => a_eq_zero,
                _ => unreachable!(),
            };
            println!("branching?:{},agtzero?:{}",branching,a_gt_zero);
            let next_pc = event.pc.wrapping_add(offset as u32);
            println!("branching pc :{},nextpc :{}",event.pc,next_pc);
            branch_columns.pc = Word::from(event.pc);
            branch_columns.next_pc = Word::from(next_pc);
            branch_columns.pc_range_checker.populate(event.pc);
            branch_columns.next_pc_range_checker.populate(next_pc);

            if branching {
                cols.branching = F::one();
                branch_columns.next_pc_nonce = F::from_canonical_u32(
                    nonce_lookup.get(&event.branch_add_lookup_id).copied().unwrap_or_default(),
                );
            } else {
                cols.not_branching = F::one();
            }
        }
    }

    // /// Populate columns related to jumping.
    // fn populate_jump<F: PrimeField>(
    //     &self,
    //     cols: &mut CpuCols<F>,
    //     event: &CpuEvent,
    //     nonce_lookup: &HashMap<LookupId, u32>,
    // ) {
    //     if event.instruction.is_jump_instruction() {
    //         let jump_columns = cols.opcode_specific_columns.jump_mut();

    //         match event.instruction.opcode {
    //             Opcode::JAL => {
    //                 let next_pc = event.pc.wrapping_add(event.b);
    //                 jump_columns.op_a_range_checker.populate(event.a);
    //                 jump_columns.pc = Word::from(event.pc);
    //                 jump_columns.pc_range_checker.populate(event.pc);
    //                 jump_columns.next_pc = Word::from(next_pc);
    //                 jump_columns.next_pc_range_checker.populate(next_pc);
    //                 jump_columns.jal_nonce = F::from_canonical_u32(
    //                     nonce_lookup.get(&event.jump_jal_lookup_id).copied().unwrap_or_default(),
    //                 );
    //             }
    //             Opcode::JALR => {
    //                 let next_pc = event.b.wrapping_add(event.c);
    //                 jump_columns.op_a_range_checker.populate(event.a);
    //                 jump_columns.next_pc = Word::from(next_pc);
    //                 jump_columns.next_pc_range_checker.populate(next_pc);
    //                 jump_columns.jalr_nonce = F::from_canonical_u32(
    //                     nonce_lookup.get(&event.jump_jalr_lookup_id).copied().unwrap_or_default(),
    //                 );
    //             }
    //             _ => unreachable!(),
    //         }
    //     }
    // }

    // /// Populate columns related to AUIPC.
    // fn populate_auipc<F: PrimeField>(
    //     &self,
    //     cols: &mut CpuCols<F>,
    //     event: &CpuEvent,
    //     nonce_lookup: &HashMap<LookupId, u32>,
    // ) {
    //     if matches!(event.instruction.opcode, Opcode::AUIPC) {
    //         let auipc_columns = cols.opcode_specific_columns.auipc_mut();

    //         auipc_columns.pc = Word::from(event.pc);
    //         auipc_columns.pc_range_checker.populate(event.pc);
    //         auipc_columns.auipc_nonce = F::from_canonical_u32(
    //             nonce_lookup.get(&event.auipc_lookup_id).copied().unwrap_or_default(),
    //         );
    //     }
    // }

    // /// Populate columns related to ECALL.
    // fn populate_ecall<F: PrimeField>(
    //     &self,
    //     cols: &mut CpuCols<F>,
    //     event: &CpuEvent,
    //     nonce_lookup: &HashMap<LookupId, u32>,
    // ) -> bool {
    //     let mut is_halt = false;

    //     if cols.selectors.is_ecall == F::one() {
    //         // The send_to_table column is the 1st entry of the op_a_access column prev_value field.
    //         // Look at `ecall_eval` in cpu/air/mod.rs for the corresponding constraint and
    //         // explanation.
    //         let ecall_cols = cols.opcode_specific_columns.ecall_mut();

    //         cols.ecall_mul_send_to_table = cols.selectors.is_ecall * cols.op_a_access.prev_value[1];

    //         let syscall_id = cols.op_a_access.prev_value[0];
    //         // let send_to_table = cols.op_a_access.prev_value[1];
    //         // let num_cycles = cols.op_a_access.prev_value[2];

    //         // Populate `is_enter_unconstrained`.
    //         ecall_cols.is_enter_unconstrained.populate_from_field_element(
    //             syscall_id - F::from_canonical_u32(SyscallCode::ENTER_UNCONSTRAINED.syscall_id()),
    //         );

    //         // Populate `is_hint_len`.
    //         ecall_cols.is_hint_len.populate_from_field_element(
    //             syscall_id - F::from_canonical_u32(SyscallCode::HINT_LEN.syscall_id()),
    //         );

    //         // Populate `is_halt`.
    //         ecall_cols.is_halt.populate_from_field_element(
    //             syscall_id - F::from_canonical_u32(SyscallCode::HALT.syscall_id()),
    //         );

    //         // Populate `is_commit`.
    //         ecall_cols.is_commit.populate_from_field_element(
    //             syscall_id - F::from_canonical_u32(SyscallCode::COMMIT.syscall_id()),
    //         );

    //         // Populate `is_commit_deferred_proofs`.
    //         ecall_cols.is_commit_deferred_proofs.populate_from_field_element(
    //             syscall_id
    //                 - F::from_canonical_u32(SyscallCode::COMMIT_DEFERRED_PROOFS.syscall_id()),
    //         );

    //         // If the syscall is `COMMIT` or `COMMIT_DEFERRED_PROOFS`, set the index bitmap and
    //         // digest word.
    //         if syscall_id == F::from_canonical_u32(SyscallCode::COMMIT.syscall_id())
    //             || syscall_id
    //                 == F::from_canonical_u32(SyscallCode::COMMIT_DEFERRED_PROOFS.syscall_id())
    //         {
    //             let digest_idx = cols.op_b_access.value().to_u32() as usize;
    //             ecall_cols.index_bitmap[digest_idx] = F::one();
    //         }

    //         // Write the syscall nonce.
    //         ecall_cols.syscall_nonce = F::from_canonical_u32(
    //             nonce_lookup.get(&event.syscall_lookup_id).copied().unwrap_or_default(),
    //         );

    //         is_halt = syscall_id == F::from_canonical_u32(SyscallCode::HALT.syscall_id());

    //         // For halt and commit deferred proofs syscalls, we need to baby bear range check one of
    //         // it's operands.
    //         if is_halt {
    //             ecall_cols.operand_to_check = event.b.into();
    //             ecall_cols.operand_range_check_cols.populate(event.b);
    //             cols.ecall_range_check_operand = F::one();
    //         }

    //         if syscall_id == F::from_canonical_u32(SyscallCode::COMMIT_DEFERRED_PROOFS.syscall_id())
    //         {
    //             ecall_cols.operand_to_check = event.c.into();
    //             ecall_cols.operand_range_check_cols.populate(event.c);
    //             cols.ecall_range_check_operand = F::one();
    //         }
    //     }

    //     is_halt
    // }

    fn pad_to_power_of_two<F: PrimeField32>(&self, shape: &Option<CoreShape>, values: &mut Vec<F>) {
        let n_real_rows = values.len() / NUM_CPU_COLS;
        let padded_nb_rows = if let Some(shape) = shape {
            1 << shape.inner[&MachineAir::<F>::name(self)]
        } else if n_real_rows < 16 {
            16
        } else {
            n_real_rows.next_power_of_two()
        };
        values.resize(padded_nb_rows * NUM_CPU_COLS, F::zero());

        // Interpret values as a slice of arrays of length `NUM_CPU_COLS`
        let rows = unsafe {
            core::slice::from_raw_parts_mut(
                values.as_mut_ptr() as *mut [F; NUM_CPU_COLS],
                values.len() / NUM_CPU_COLS,
            )
        };
    }

    fn populate_alu<F: PrimeField>(
        &self,
        cols: &mut CpuCols<F>,
        event: &CpuEvent,
        nonce_lookup: &HashMap<LookupId, u32>    
    ) {
       match event.instruction
       {
            Instruction::I32GtS|Instruction::I32GtU|
            Instruction::I32GeS|Instruction::I32GeU|
            Instruction::I32LeS|Instruction::I32LeU|
            Instruction::I32Eqz |Instruction::I32Eq |
            Instruction::I32Ne=>{
                let alu = cols.opcode_specific_columns.alu_mut();
                alu.arg1_eq_arg2 = F::from_bool(event.arg1 == event.arg2);
                alu.arg1_gt_arg2 = F::from_bool(event.arg1 > event.arg2);
                alu.arg1_lt_arg2 = F::from_bool(event.arg1 < event.arg2);
                alu.res_bool = F::from_canonical_u32(event.res);

                alu.a_lt_b_nonce = F::from_canonical_u32(
                    nonce_lookup.get(&event.branch_lt_lookup_id).copied().unwrap_or_default(),
                );
    
                alu.a_gt_b_nonce = F::from_canonical_u32(
                    nonce_lookup.get(&event.branch_gt_lookup_id).copied().unwrap_or_default(),
                );
            }
             _=>{
                return;
            }
       }
    }

    fn populate_funccall<F: PrimeField>(
        &self,
        cols: &mut CpuCols<F>,
        event: &CpuEvent,
    
    ){
        if event.instruction.is_call_instruction(){
            let funccall= cols.opcode_specific_columns.funccall_mut();
            if event.depth ==0{
                funccall.depth_is_zero = F::one();
            }
            match event.instruction{
                Instruction::Return(drop_keep)=>{
                    if drop_keep.drop()==1&&drop_keep.keep()==1{
                        funccall.dropkeep_is_one= F::one();
                    }
                    if event.depth!=0{
                        funccall.return_depth_is_not_zero=F::one();
                    }
                },
                _=>(),
            }
        }
      
    } 

}
