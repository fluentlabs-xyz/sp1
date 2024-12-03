use p3_field::PrimeField;
use rwasm::rwasm::InstructionExtra;
use sp1_derive::AlignedBorrow;
use sp1_rwasm_executor::{Instruction, Opcode};
use std::{
    mem::{size_of, transmute},
    vec::IntoIter,
};

use crate::utils::indices_arr;

pub const NUM_OPCODE_SELECTOR_COLS: usize = size_of::<OpcodeSelectorCols<u8>>();
pub const OPCODE_SELECTORS_COL_MAP: OpcodeSelectorCols<usize> = make_selectors_col_map();

/// Creates the column map for the CPU.
const fn make_selectors_col_map() -> OpcodeSelectorCols<usize> {
    let indices_arr = indices_arr::<NUM_OPCODE_SELECTOR_COLS>();
    unsafe {
        transmute::<[usize; NUM_OPCODE_SELECTOR_COLS], OpcodeSelectorCols<usize>>(indices_arr)
    }
}

/// The column layout for opcode selectors.
#[derive(AlignedBorrow, Clone, Copy, Default, Debug)]
#[repr(C)]
pub struct OpcodeSelectorCols<T> {
    /// Table selectors for opcodes.
    pub is_alu: T,

    /// Table selectors for opcodes.
    pub is_ecall: T,

    pub is_auipc: T,
    pub is_unimpl: T,

    pub is_iadd32: T,
}

impl<F: PrimeField> OpcodeSelectorCols<F> {
    pub fn populate(&mut self, instruction: Instruction) {
        let op_code = instruction.code_value() as u32;
        if instruction.is_alu_instruction() {
            self.is_alu = F::one();
        } else if instruction.is_ecall_instruction() {
            self.is_ecall = F::one();
        } else if instruction.is_memory_instruction() {
        } else if instruction.is_branch_instruction() {
        }
    }
}

impl<T> IntoIterator for OpcodeSelectorCols<T> {
    type Item = T;
    type IntoIter = IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        let columns = vec![self.is_alu, self.is_ecall, self.is_auipc, self.is_unimpl];
        assert_eq!(columns.len(), NUM_OPCODE_SELECTOR_COLS);
        columns.into_iter()
    }
}
