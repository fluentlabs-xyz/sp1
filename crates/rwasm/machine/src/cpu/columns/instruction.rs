use p3_field::PrimeField;
use rwasm_executor::rwasm_ins_to_code;
use sp1_derive::AlignedBorrow;
use sp1_stark::Word;
use std::{iter::once, mem::size_of, vec::IntoIter};
use rwasm::{engine::bytecode::Instruction, rwasm::InstructionExtra};
pub const NUM_INSTRUCTION_COLS: usize = size_of::<InstructionCols<u8>>();

/// The column layout for instructions.
#[derive(AlignedBorrow, Clone, Copy, Default, Debug)]
#[repr(C)]
pub struct InstructionCols<T> {
    /// The opcode for this cycle.
    pub opcode: T,

    pub aux_val: T,


}

impl<F: PrimeField> InstructionCols<F> {
    pub fn populate(&mut self, instruction: &Instruction) {
        self.opcode = F::from_canonical_u32(rwasm_ins_to_code(*instruction));
        self.aux_val= F::from_canonical_u32(instruction.aux_value().unwrap().into());
    }
}

impl<T> IntoIterator for InstructionCols<T> {
    type Item = T;
    type IntoIter = IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        once(self.opcode)
            .chain(once(self.aux_val))
            .collect::<Vec<_>>()
            .into_iter()
    }
}
