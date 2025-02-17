use serde::{Deserialize, Serialize};

use crate::Instruction;

use super::{memory::MemoryRecordEnum, LookupId, MemoryReadRecord, MemoryWriteRecord};

/// CPU Event.
///
/// This object encapsulates the information needed to prove a CPU operation. This includes its
/// shard, opcode, operands, and other relevant information.
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct CpuEvent {
    /// The shard number.
    pub shard: u32,
    /// The clock cycle.
    pub clk: u32,
    /// The program counter.
    pub pc: u32,
    /// The next program counter.
    pub next_pc: u32,
    /// stack pointer 
    pub sp: u32,
    /// stack pointer of next cycle
    pub next_sp: u32,

    /// function depth:
    pub depth:u32,

    /// funnction depth for next cycle.
    pub next_depth:u32,
    
    /// The instruction.
    pub instruction: Instruction,
    /// the first argument of an rwasm op
    pub arg1:u32,
    /// the second argument of an rwasm op
    pub arg2:u32,
    /// result of an op
    pub res :u32,
    /// the memory record of reading the first argument
    pub arg1_record:Option<MemoryReadRecord>,   
    /// the memory record of reading the second argument
    pub arg2_record:Option<MemoryReadRecord>,
    /// the memory record of writing back the result
    pub res_record:Option<MemoryWriteRecord>,
    /// The exit code.
    pub exit_code: u32,
    /// The ALU lookup id.
    pub alu_lookup_id: LookupId,
    /// The syscall lookup id.
    pub syscall_lookup_id: LookupId,
    /// The memory add lookup id.
    pub memory_add_lookup_id: LookupId,
    /// The memory sub lookup id.
    pub memory_sub_lookup_id: LookupId,
    /// The branch gt lookup id.
    pub branch_gt_lookup_id: LookupId,
    /// The branch lt lookup id.
    pub branch_lt_lookup_id: LookupId,
    /// The branch add lookup id.
    pub branch_add_lookup_id: LookupId,
    /// The jump jal lookup id.
    pub jump_jal_lookup_id: LookupId,
    /// The jump jalr lookup id.
    pub jump_jalr_lookup_id: LookupId,
    /// The auipc lookup id.
    pub auipc_lookup_id: LookupId,
}
