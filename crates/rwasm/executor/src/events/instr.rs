use rwasm::Opcode;
use serde::{Deserialize, Serialize};

use super::MemoryRecordEnum;

/// Alu Opcode Event.
///
/// This object encapsulated the information needed to prove a RISC-V ALU operation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[repr(C)]
pub struct AluEvent {
    /// The program counter.
    pub pc: u32,
    /// riscv opcode
    pub opcode: Opcode,

    /// The first operand value.
    pub a: u32,
    /// The second operand value.
    pub b: u32,
    /// The third operand value.
    pub c: u32,
    ///
    pub code: u32,
}

impl AluEvent {
    /// Create a new [`AluEvent`].
    #[must_use]
    pub fn new(pc: u32, opcode: Opcode, a: u32, b: u32, c: u32, code: u32) -> Self {
        Self { pc, opcode, a, b, c, code }
    }
}

/// Memory Opcode Event.
///
/// This object encapsulated the information needed to prove a RISC-V memory operation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[repr(C)]
pub struct MemInstrEvent {
    /// The shard.
    pub shard: u32,
    /// The clk.
    pub clk: u32,
    /// The program counter.
    pub pc: u32,
    /// The Opcode
    pub opcode: Opcode,

    /// The first operand value.
    pub raw_addr: u32,
    /// The second operand value.
    pub offset: u32,
    /// The third operand value.
    pub res: u32,
    /// The memory access record for memory operations.
    pub mem_access: MemoryRecordEnum,
}

impl MemInstrEvent {
    /// Create a new [`MemInstrEvent`].
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        shard: u32,
        clk: u32,
        pc: u32,
        opcode: Opcode,
        raw_addr: u32,
        offset: u32,
        res: u32,

        mem_access: MemoryRecordEnum,
    ) -> Self {
        Self { shard, clk, pc, opcode, raw_addr, offset, res, mem_access }
    }
}

/// Branch Opcode Event.
///
/// This object encapsulated the information needed to prove a RISC-V branch operation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[repr(C)]
pub struct BranchEvent {
    /// The program counter.
    pub pc: u32,
    /// The next program counter.
    pub next_pc: u32,
    /// The Opcode
    pub opcode: Opcode,

    /// The first operand value.
    pub res: u32,
    /// The second operand value.
    pub arg1: u32,
    /// The third operand value.
    pub arg2: u32,
}

impl BranchEvent {
    /// Create a new [`BranchEvent`].
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(pc: u32, next_pc: u32, opcode: Opcode, a: u32, b: u32, c: u32) -> Self {
        Self { pc, next_pc, opcode, res: a, arg1: b, arg2: c }
    }
}

/// Const Opcode Event.
///
/// This object encapsulated the information needed to prove a RISC-V branch operation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[repr(C)]
pub struct ConstEvent {
    /// The program counter.
    pub pc: u32,
    /// The Opcode
    pub opcode: Opcode,
    /// The value
    pub value: u32,
}

impl ConstEvent {
    /// Create a new [`BranchEvent`].
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(pc: u32, opcode: Opcode, value: u32) -> Self {
        Self { pc, opcode, value }
    }
}
///TODO: this event is for changing the state of rwasm engine. not finished yet.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[repr(C)]
pub struct SysStateEvent {
    /// The fuel before op
    pub fuel: u32,
    /// The fuel after op
    pub next_fuel:u32,
    /// The Opcode
    pub opcode: Opcode,
    /// maximium memory before op
    pub max_memory:u32,
    /// maximium memory after op
    pub next_max_memory:u32,
}

impl SysStateEvent {
    ///create a new system state event
    #[must_use] 
    pub fn new(opcode:Opcode,fuel:u32,next_fuel:u32,max_memory:u32,next_max_memory:u32)->Self{
        SysStateEvent { fuel, next_fuel,
             opcode,
              max_memory, 
              next_max_memory,
             }
    }
}
