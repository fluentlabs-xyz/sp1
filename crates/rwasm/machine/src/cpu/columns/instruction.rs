use p3_field::PrimeField;
use rwasm::{engine::bytecode::Instruction, rwasm::InstructionExtra};
use sp1_derive::AlignedBorrow;

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
    pub is_nullary:T,
    pub is_unary: T,
    pub is_binary: T,
    pub is_memory: T,
    pub is_branching: T,
    pub is_call:T,
    pub is_local:T,
    pub aux_val: Word<T>,
}

impl<F: PrimeField> InstructionCols<F> {
    pub fn populate(&mut self, instruction: Instruction) {

        let sp1_op = rwasm_ins_to_sp1_alu(&instruction);
        match sp1_op{
            Some(sp1_op)=>{self.opcode=sp1_op.as_field();}
            None => (),
        }
        self.is_nullary=F::from_bool(instruction.is_nullary());
        self.is_unary = F::from_bool(instruction.is_unary_instruction());
        self.is_binary = F::from_bool(instruction.is_binary_instruction());
        self.is_memory = F::from_bool(instruction.is_memory_instruction());
        self.is_branching = F::from_bool(instruction.is_branch_instruction());
        self.is_call = F::from_bool(instruction.is_call_instruction());
        match instruction{
            Instruction::LocalGet(_)|
            Instruction::LocalSet(_)|
            Instruction::LocalTee(_)=>{
                self.is_branching = F::one()
            }
            _=>()
        }
        if let Some(aux_val) = instruction.aux_value(){
           match instruction{
             Instruction::Br(_)|
             Instruction::BrIfEqz(_)|
             Instruction::BrIfNez(_)=>{
                let aux_val:i32= aux_val.into();
                self.aux_val = (aux_val as u32).into();
                println!("instruction: {:?},aux_val:{}",instruction,aux_val);
             },
             _=>{
                let aux_val:u32= aux_val.into();
                self.aux_val = aux_val.into();
                println!("instruction: {:?},aux_val:{}",instruction,aux_val);
             }
           }
            
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
