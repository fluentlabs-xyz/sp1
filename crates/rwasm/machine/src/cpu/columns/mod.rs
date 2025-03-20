mod alu;
mod auipc;
mod branch;
mod ecall;
mod instruction;
mod jump;
mod memory;
mod funccall;
mod opcode;
mod opcode_specific;
pub use alu::*;
pub use auipc::*;
pub use branch::*;
pub use ecall::*;
pub use instruction::*;
pub use jump::*;
pub use memory::*;
pub use opcode::*;
pub use opcode_specific::*;
pub use funccall::*;

use p3_util::indices_arr;
use sp1_derive::AlignedBorrow;
use sp1_stark::Word;
use std::mem::{size_of, transmute};

use crate::memory::{MemoryCols, MemoryReadCols, MemoryReadWriteCols, MemoryWriteCols};

pub const NUM_CPU_COLS: usize = size_of::<CpuCols<u8>>();

pub const CPU_COL_MAP: CpuCols<usize> = make_col_map();

/// The column layout for the CPU.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct CpuCols<T: Copy> {
    /// The current shard.
    pub shard: T,

    pub nonce: T,

    /// The clock cycle value.  This should be within 24 bits.
    pub clk: T,
    /// The least significant 16 bit limb of clk.
    pub clk_16bit_limb: T,
    /// The most significant 8 bit limb of clk.
    pub clk_8bit_limb: T,

    /// The program counter value.
    pub pc: T,

    /// The expected next program counter value.
    pub next_pc: T,

    pub sp: T,
    
    pub next_sp: T,

    pub depth :T,
    pub next_depth:T,
    
    /// Columns related to the instruction.
    pub instruction: InstructionCols<T>,

    /// Selectors for the opcode.
    pub selectors: OpcodeSelectorCols<T>,

    /// Operand values, either from registers or immediate values.
    pub op_arg1_access: MemoryReadCols<T>,
    pub op_arg2_access: MemoryReadCols<T>,
    pub op_res_access: MemoryWriteCols<T>,

    pub op_arg1: Word<T>,
    pub op_arg2: Word<T>,
    pub res: Word<T>,

    pub opcode_specific_columns: OpcodeSpecificCols<T>,

    /// Selector to label whether this row is a non padded row.
    pub is_real: T,

    /// The branching column is equal to:
    ///
    /// > is_beq & a_eq_b ||
    /// > is_bne & (a_lt_b | a_gt_b) ||
    /// > (is_blt | is_bltu) & a_lt_b ||
    /// > (is_bge | is_bgeu) & (a_eq_b | a_gt_b)
    pub branching: T,

    /// The not branching column is equal to:
    ///
    /// > is_beq & !a_eq_b ||
    /// > is_bne & !(a_lt_b | a_gt_b) ||
    /// > (is_blt | is_bltu) & !a_lt_b ||
    /// > (is_bge | is_bgeu) & !(a_eq_b | a_gt_b)
    pub not_branching: T,

  

    /// The unsigned memory value is the value after the offset logic is applied. Used for the load
    /// memory opcodes (i.e. LB, LH, LW, LBU, and LHU).
    pub unsigned_mem_val: Word<T>,

    pub unsigned_mem_val_nonce: T,

    /// The result of selectors.is_ecall * the send_to_table column for the ECALL opcode.
    pub ecall_mul_send_to_table: T,

    /// The result of selectors.is_ecall * (is_halt || is_commit_deferred_proofs)
    pub ecall_range_check_operand: T,

    /// This is true for all instructions that are not jumps, branches, and halt.  Those
    /// instructions may move the program counter to a non sequential instruction.
    pub is_sequential_instr: T,
    /// if the return is real, we will read the func frame from funccall area 
    /// that is when depth is larger than 1
    pub is_real_return: T,
    /// when drop keep is non zero, we should do memory check TODO: remove this when dropkeep is removed.
    pub is_drop_keep_one:T,
}

impl<T: Copy> CpuCols<T> {
    /// Gets the value of the first operand.
    pub fn op_arg1_val(&self) -> Word<T> {
        *self.op_arg1_access.value()
    }

    /// Gets the value of the second operand.
    pub fn op_arg2_val(&self) -> Word<T> {
        *self.op_arg2_access.value()
    }

    /// Gets the value of the third operand.
    pub fn op_res_val(&self) -> Word<T> {
        *self.op_res_access.value()
    }
}

/// Creates the column map for the CPU.
const fn make_col_map() -> CpuCols<usize> {
    let indices_arr = indices_arr::<NUM_CPU_COLS>();
    unsafe { transmute::<[usize; NUM_CPU_COLS], CpuCols<usize>>(indices_arr) }
}
