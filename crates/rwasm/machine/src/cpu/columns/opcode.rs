use p3_field::PrimeField;
use rwasm::{engine::bytecode::Instruction, rwasm::InstructionExtra};
use sp1_derive::AlignedBorrow;
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
    pub is_ordinary_alu: T,
    pub is_comparison_alu:T,
    /// Table selectors for opcodes.
    pub is_memory:T,
    pub is_ecall: T,

    pub is_auipc: T,
    pub is_unimpl: T,
    // The following does not need selector because 
    // they are check directly with sp1 alu.
    // i32add, i32sub,i32mul,i32sub,i32divu, i32divs,i32remu,
    // i32rems,i32and,i32or,i32xor,i32shru,i32shl,i32shrs
    pub is_i32les: T,
    pub is_i32leu: T,
    pub is_i32gts: T,
    pub is_i32gtu: T,
    pub is_i32ges: T,
    pub is_i32geu: T,
    pub is_i32eq: T,
    pub is_i32ne: T,
    pub is_i32eqz: T,

    pub is_i32load: T,
    pub is_i32load16s: T,
    pub is_i32load16u: T,
    pub is_i32load8u:T,
    pub is_i32load8s:T,
    pub is_i32store:T,
    pub is_i32store16:T,
    pub is_i32store8:T,
}

impl<F: PrimeField> OpcodeSelectorCols<F> {
    pub fn populate(&mut self, instruction: Instruction) {
        
        if instruction.is_alu_instruction() {
            // I32 Lts and I32 Ltu can use sp1 circuit directly so 
            // they do not need go to compare
            match instruction {
                Instruction::I32GtS| Instruction::I32GtU |
                Instruction::I32GeS | Instruction::I32GeU|
                Instruction::I32LeS |Instruction::I32LeU|
                Instruction::I32Eqz |Instruction::I32Eq |
                Instruction::I32Ne=>{
                    self.is_comparison_alu = F::one();
                }
                _=>{
                    self.is_ordinary_alu = F::one();
                }
            }
            self.is_alu = F::one();
        } else if instruction.is_ecall_instruction() {
            self.is_ecall = F::one();
        } else if instruction.is_memory_instruction() {
            self.is_memory = F::one();
        } else if instruction.is_branch_instruction() {
            todo!()
        }
        match instruction{
            Instruction::I32Eqz => { self.is_i32eqz = F::one();},
            Instruction::I32Eq => {self.is_i32eq=F::one()}
            Instruction::I32Ne => {self.is_i32ne=F::one()},
            Instruction::I32GtS => {self.is_i32gts=F::one()},
            Instruction::I32GtU => {self.is_i32gtu=F::one()},
            Instruction::I32LeS => {self.is_i32les=F::one()},
            Instruction::I32LeU => {self.is_i32leu=F::one()},
            Instruction::I32GeS => {self.is_i32ges=F::one()},
            Instruction::I32GeU => {self.is_i32geu=F::one()},
            Instruction::I64Eqz => {self.is_i32eqz=F::one()},
            Instruction::I64Eq => {self.is_i32eq=F::one()},
            Instruction::I64Ne => {self.is_i32ne=F::one()},
            Instruction::I32Load(_)=>{self.is_i32load=F::one()},
            Instruction::I32Load16S(_)=>{self.is_i32load=F::one()},
            Instruction::I32Load16U(_)=>{self.is_i32load=F::one()},
            Instruction::I32Load8S(_)=>{self.is_i32load=F::one()},
            Instruction::I32Load8U(_)=>{self.is_i32load=F::one()},
            Instruction::I32Store(_)=>{self.is_i32store=F::one()},
            Instruction::I32Store16(_)=>{self.is_i32store16=F::one()},
            Instruction::I32Store8(_)=>{self.is_i32store8=F::one()},
           _=>{}
        }

        
    }
}

impl<T> IntoIterator for OpcodeSelectorCols<T> {
    type Item = T;
    type IntoIter = IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        let columns = vec![self.is_alu, self.is_ordinary_alu,self.is_comparison_alu,self.is_memory,self.is_ecall, self.is_auipc, self.is_unimpl,
        self.is_i32les,self.is_i32leu,
        self.is_i32ges,self.is_i32geu,self.is_i32gts,self.is_i32gtu,
        self.is_i32eq,self.is_i32ne,self.is_i32eqz,
        self.is_i32load,self.is_i32load16s,self.is_i32load16u,self.is_i32load8s,self.is_i32load8u,
        self.is_i32store,self.is_i32store16,self.is_i32store8];
        assert_eq!(columns.len(), NUM_OPCODE_SELECTOR_COLS); 
        columns.into_iter()
    }
}
