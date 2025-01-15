use p3_field::PrimeField;
use rwasm::rwasm::InstructionExtra;
use sp1_derive::AlignedBorrow;
use sp1_rwasm_executor::{Instruction, Register};
use sp1_stark::Word;
use std::{iter::once, mem::size_of, vec::IntoIter};

use crate::cpu::utils::rwasm_ins_to_sp1_alu;
pub const NUM_INSTRUCTION_COLS: usize = size_of::<InstructionCols<u8>>();

/// The column layout for instructions.
#[derive(AlignedBorrow, Clone, Copy, Default, Debug)]
#[repr(C)]
pub struct InstructionCols<T> {
    /// The opcode for this cycle.
    pub opcode: T,
    pub is_unary: T,
    pub is_binary: T,
    pub is_memory: T,
    pub aux_val: Word<T>,
}

impl<F: PrimeField> InstructionCols<F> {
    pub fn populate(&mut self, instruction: Instruction) {

        let sp1_op = rwasm_ins_to_sp1_alu(&instruction);
        match sp1_op{
            Some(sp1_op)=>{self.opcode=sp1_op.as_field();}
            None => (),
        }
        self.is_unary = F::from_bool(instruction.is_unary_instruction());
        self.is_binary = F::from_bool(instruction.is_binary_instruction());
        self.is_memory = F::from_bool(instruction.is_memory_instruction());
        println!("binary:{}",instruction.is_binary_instruction());
        println!("unary:{}",instruction.is_unary_instruction());
        println!("memory:{}",instruction.is_memory_instruction());
        if let Some(aux_val) = instruction.aux_value(){
            let aux_val:u32 = aux_val.into();
            self.aux_val = aux_val.into();
        } else{
            self.aux_val = 0.into()
        }
        
    }
}

impl<T> IntoIterator for InstructionCols<T> {
    type Item = T;
    type IntoIter = IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        once(self.opcode)
            .collect::<Vec<_>>()
            .into_iter()
    }
}
