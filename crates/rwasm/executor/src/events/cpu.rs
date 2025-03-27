use rwasm::engine::bytecode::Instruction;
use serde::{Deserialize, Serialize};
use crate::events::{MemoryReadRecord, MemoryWriteRecord};
use super::memory::MemoryRecordEnum;

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
    /// function depth for next cycle.
    pub next_depth:u32,
    /// The instruction.
    pub instruction: Instruction,
    /// the first argument of a rwasm op
    pub arg1: u32,
    /// The first operand memory record.
    /// the second argument of a rwasm op
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
}
