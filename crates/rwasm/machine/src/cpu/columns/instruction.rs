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
    pub aux_val: Word<T>,
    pub is_nullary:T,
    pub is_unary: T,
    pub is_binary: T,
    pub is_memory: T,
    pub is_branching: T,
    pub is_call:T,
    pub is_local:T,
    /// Table selectors for opcodes.
    pub is_alu: T,
    pub is_ordinary_alu: T,
    pub is_comparison_alu:T,
    pub is_skipped:T,
    /// Table selectors for opcodes.
    pub is_ecall: T,

    pub is_auipc: T,
    pub is_unimpl: T,
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

    pub is_br:T,
    pub is_brifnez:T,
    pub is_brifeqz:T,

    pub is_localget:T,
    pub is_localset:T,
    pub is_localtee:T,
    pub is_i32const:T,

    pub is_callinternal:T,
    pub is_return:T,


}

impl<F: PrimeField> InstructionCols<F> {
    pub fn populate(&mut self, instruction: &Instruction) {
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
                // println!("instruction: {:?},aux_val:{}",instruction,aux_val);
             },
             _=>{
                let aux_val:u32= aux_val.into();
                self.aux_val = aux_val.into();
                // println!("instruction: {:?},aux_val:{}",instruction,aux_val);
             }
           }
            
        } else{
            self.aux_val = 0.into()
        }
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
            Instruction::I32Load16S(_)=>{self.is_i32load16s=F::one()},
            Instruction::I32Load16U(_)=>{self.is_i32load16u=F::one()},
            Instruction::I32Load8S(_)=>{self.is_i32load8s=F::one()},
            Instruction::I32Load8U(_)=>{self.is_i32load8u=F::one()},
            Instruction::I32Store(_)=>{self.is_i32store=F::one()},
            Instruction::I32Store16(_)=>{self.is_i32store16=F::one()},
            Instruction::I32Store8(_)=>{self.is_i32store8=F::one()},
            Instruction::Br(_)=>{self.is_br=F::one()},
            Instruction::BrIfEqz(_)=>{self.is_brifeqz=F::one()},
            Instruction::BrIfNez(_)=>{self.is_brifnez=F::one()},
            Instruction::LocalGet(_)=>{self.is_localget=F::one()},
            Instruction::LocalSet(_)=>{self.is_localset=F::one()},
            Instruction::LocalTee(_)=>{self.is_localtee=F::one()},
            Instruction::I32Const(_)=>{self.is_i32const=F::one()},
            Instruction::CallInternal(_)=>{self.is_callinternal=F::one()},
            Instruction::Return(_)=>(self.is_return=F::one()),
            Instruction::ConsumeFuel(_)=>{self.is_skipped=F::one()},
            Instruction::SignatureCheck(_)=>{self.is_skipped=F::one()},
            Instruction::Drop=>{self.is_skipped=F::one()},
           _=>{}
        }
        
    }
}

impl<T> IntoIterator for InstructionCols<T> {
    type Item = T;
    type IntoIter = IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        let columns = vec![self.is_alu, self.is_ordinary_alu,self.is_comparison_alu,
        self.is_branching, self.is_memory,self.is_ecall, self.is_auipc, self.is_unimpl,
        self.is_i32les,self.is_i32leu,
        self.is_i32ges,self.is_i32geu,self.is_i32gts,self.is_i32gtu,
        self.is_i32eq,self.is_i32ne,self.is_i32eqz,
        self.is_i32load,self.is_i32load16s,self.is_i32load16u,self.is_i32load8s,self.is_i32load8u,
        self.is_i32store,self.is_i32store16,self.is_i32store8,
        self.is_br,self.is_brifeqz,self.is_brifnez,
        self.is_localget,self.is_localset,self.is_localtee,self.is_i32const,
        self.is_callinternal,self.is_return,
        self.is_skipped,];
       
        columns.into_iter()
    }
}
