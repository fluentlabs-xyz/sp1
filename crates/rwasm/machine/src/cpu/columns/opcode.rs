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
    pub is_ecall: T,

    pub is_auipc: T,
    pub is_unimpl: T,

    pub is_i32add: T,
    pub is_i32sub: T,
    pub is_i32mul: T,
    pub is_i32divu:T,
    pub is_i32divs:T,
    pub is_i32remu: T,
    pub is_i32rem: T,

    pub is_i32lts: T,
    pub is_i32ltu: T,
    pub is_i32les: T,
    pub is_i32leu: T,
    pub is_i32gts: T,
    pub is_i32gtu: T,
    pub is_i32ges: T,
    pub is_i32geu: T,
    pub is_i32eq: T,
    pub is_i32ne: T,
    pub is_i32eqz: T,
}

impl<F: PrimeField> OpcodeSelectorCols<F> {
    pub fn populate(&mut self, instruction: Instruction) {
        let op_code = instruction.code_value() as u32;
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
        } else if instruction.is_ecall_instruction() {
            self.is_ecall = F::one();
        } else if instruction.is_memory_instruction() {
            todo!()
        } else if instruction.is_branch_instruction() {
            todo!()
        }
        match instruction{
            Instruction::LocalGet(local_depth) => todo!(),
            Instruction::LocalSet(local_depth) => todo!(),
            Instruction::LocalTee(local_depth) => todo!(),
            Instruction::Br(branch_offset) => todo!(),
            Instruction::BrIfEqz(branch_offset) => todo!(),
            Instruction::BrIfNez(branch_offset) => todo!(),
            Instruction::BrAdjust(branch_offset) => todo!(),
            Instruction::BrAdjustIfNez(branch_offset) => todo!(),
            Instruction::BrTable(branch_table_targets) => todo!(),
            Instruction::Unreachable => todo!(),
            Instruction::ConsumeFuel(block_fuel) => todo!(),
            Instruction::Return(drop_keep) => todo!(),
            Instruction::ReturnIfNez(drop_keep) => todo!(),
            Instruction::ReturnCallInternal(compiled_func) => todo!(),
            Instruction::ReturnCall(func_idx) => todo!(),
            Instruction::ReturnCallIndirect(signature_idx) => todo!(),
            Instruction::CallInternal(compiled_func) => todo!(),
            Instruction::Call(func_idx) => todo!(),
            Instruction::CallIndirect(signature_idx) => todo!(),
            Instruction::SignatureCheck(signature_idx) => todo!(),
            Instruction::Drop => todo!(),
            Instruction::Select => todo!(),
            Instruction::GlobalGet(global_idx) => todo!(),
            Instruction::GlobalSet(global_idx) => todo!(),
            Instruction::I32Load(address_offset) => todo!(),
            Instruction::I64Load(address_offset) => todo!(),
            Instruction::F32Load(address_offset) => todo!(),
            Instruction::F64Load(address_offset) => todo!(),
            Instruction::I32Load8S(address_offset) => todo!(),
            Instruction::I32Load8U(address_offset) => todo!(),
            Instruction::I32Load16S(address_offset) => todo!(),
            Instruction::I32Load16U(address_offset) => todo!(),
            Instruction::I64Load8S(address_offset) => todo!(),
            Instruction::I64Load8U(address_offset) => todo!(),
            Instruction::I64Load16S(address_offset) => todo!(),
            Instruction::I64Load16U(address_offset) => todo!(),
            Instruction::I64Load32S(address_offset) => todo!(),
            Instruction::I64Load32U(address_offset) => todo!(),
            Instruction::I32Store(address_offset) => todo!(),
            Instruction::I64Store(address_offset) => todo!(),
            Instruction::F32Store(address_offset) => todo!(),
            Instruction::F64Store(address_offset) => todo!(),
            Instruction::I32Store8(address_offset) => todo!(),
            Instruction::I32Store16(address_offset) => todo!(),
            Instruction::I64Store8(address_offset) => todo!(),
            Instruction::I64Store16(address_offset) => todo!(),
            Instruction::I64Store32(address_offset) => todo!(),
            Instruction::MemorySize => todo!(),
            Instruction::MemoryGrow => todo!(),
            Instruction::MemoryFill => todo!(),
            Instruction::MemoryCopy => todo!(),
            Instruction::MemoryInit(data_segment_idx) => todo!(),
            Instruction::DataDrop(data_segment_idx) => todo!(),
            Instruction::TableSize(table_idx) => todo!(),
            Instruction::TableGrow(table_idx) => todo!(),
            Instruction::TableFill(table_idx) => todo!(),
            Instruction::TableGet(table_idx) => todo!(),
            Instruction::TableSet(table_idx) => todo!(),
            Instruction::TableCopy(table_idx) => todo!(),
            Instruction::TableInit(element_segment_idx) => todo!(),
            Instruction::ElemDrop(element_segment_idx) => todo!(),
            Instruction::RefFunc(func_idx) => todo!(),
            Instruction::I32Const(untyped_value) => todo!(),
            Instruction::I64Const(untyped_value) => todo!(),
            Instruction::F32Const(untyped_value) => todo!(),
            Instruction::F64Const(untyped_value) => todo!(),
            Instruction::ConstRef(const_ref) => todo!(),
            Instruction::I32Eqz => { self.is_i32eqz = F::one();},
            Instruction::I32Eq => {self.is_i32eq=F::one()}
            Instruction::I32Ne => {self.is_i32ne=F::one()},
            Instruction::I32LtS => {self.is_i32lts=F::one()},
            Instruction::I32LtU => {self.is_i32ltu=F::one()},
            Instruction::I32GtS => {self.is_i32gts=F::one()},
            Instruction::I32GtU => {self.is_i32gtu=F::one()},
            Instruction::I32LeS => {self.is_i32les=F::one()},
            Instruction::I32LeU => {self.is_i32leu=F::one()},
            Instruction::I32GeS => {self.is_i32ges=F::one()},
            Instruction::I32GeU => {self.is_i32geu=F::one()},
            Instruction::I64Eqz => {self.is_i32eqz=F::one()},
            Instruction::I64Eq => {self.is_i32eq=F::one()},
            Instruction::I64Ne => {self.is_i32ne=F::one()},
            Instruction::I64LtS => todo!(),
            Instruction::I64LtU => todo!(),
            Instruction::I64GtS => todo!(),
            Instruction::I64GtU => todo!(),
            Instruction::I64LeS => todo!(),
            Instruction::I64LeU => todo!(),
            Instruction::I64GeS => todo!(),
            Instruction::I64GeU => todo!(),
            Instruction::F32Eq => todo!(),
            Instruction::F32Ne => todo!(),
            Instruction::F32Lt => todo!(),
            Instruction::F32Gt => todo!(),
            Instruction::F32Le => todo!(),
            Instruction::F32Ge => todo!(),
            Instruction::F64Eq => todo!(),
            Instruction::F64Ne => todo!(),
            Instruction::F64Lt => todo!(),
            Instruction::F64Gt => todo!(),
            Instruction::F64Le => todo!(),
            Instruction::F64Ge => todo!(),
            Instruction::I32Clz => todo!(),
            Instruction::I32Ctz => todo!(),
            Instruction::I32Popcnt => todo!(),
            Instruction::I32Add => {self.is_i32add=F::one()},
            Instruction::I32Sub => {self.is_i32sub=F::one()},
            Instruction::I32Mul => {self.is_i32mul=F::one()},
            Instruction::I32DivS => {self.is_i32divs=F::one()},
            Instruction::I32DivU => {self.is_i32divu=F::one()},
            Instruction::I32RemS => {self.is_i32rem=F::one()},
            Instruction::I32RemU => {self.is_i32remu=F::one()},
            Instruction::I32And => todo!(),
            Instruction::I32Or => todo!(),
            Instruction::I32Xor => todo!(),
            Instruction::I32Shl => todo!(),
            Instruction::I32ShrS => todo!(),
            Instruction::I32ShrU => todo!(),
            Instruction::I32Rotl => todo!(),
            Instruction::I32Rotr => todo!(),
            Instruction::I64Clz => todo!(),
            Instruction::I64Ctz => todo!(),
            Instruction::I64Popcnt => todo!(),
            Instruction::I64Add => todo!(),
            Instruction::I64Sub => todo!(),
            Instruction::I64Mul => todo!(),
            Instruction::I64DivS => todo!(),
            Instruction::I64DivU => todo!(),
            Instruction::I64RemS => todo!(),
            Instruction::I64RemU => todo!(),
            Instruction::I64And => todo!(),
            Instruction::I64Or => todo!(),
            Instruction::I64Xor => todo!(),
            Instruction::I64Shl => todo!(),
            Instruction::I64ShrS => todo!(),
            Instruction::I64ShrU => todo!(),
            Instruction::I64Rotl => todo!(),
            Instruction::I64Rotr => todo!(),
            Instruction::F32Abs => todo!(),
            Instruction::F32Neg => todo!(),
            Instruction::F32Ceil => todo!(),
            Instruction::F32Floor => todo!(),
            Instruction::F32Trunc => todo!(),
            Instruction::F32Nearest => todo!(),
            Instruction::F32Sqrt => todo!(),
            Instruction::F32Add => todo!(),
            Instruction::F32Sub => todo!(),
            Instruction::F32Mul => todo!(),
            Instruction::F32Div => todo!(),
            Instruction::F32Min => todo!(),
            Instruction::F32Max => todo!(),
            Instruction::F32Copysign => todo!(),
            Instruction::F64Abs => todo!(),
            Instruction::F64Neg => todo!(),
            Instruction::F64Ceil => todo!(),
            Instruction::F64Floor => todo!(),
            Instruction::F64Trunc => todo!(),
            Instruction::F64Nearest => todo!(),
            Instruction::F64Sqrt => todo!(),
            Instruction::F64Add => todo!(),
            Instruction::F64Sub => todo!(),
            Instruction::F64Mul => todo!(),
            Instruction::F64Div => todo!(),
            Instruction::F64Min => todo!(),
            Instruction::F64Max => todo!(),
            Instruction::F64Copysign => todo!(),
            Instruction::I32WrapI64 => todo!(),
            Instruction::I32TruncF32S => todo!(),
            Instruction::I32TruncF32U => todo!(),
            Instruction::I32TruncF64S => todo!(),
            Instruction::I32TruncF64U => todo!(),
            Instruction::I64ExtendI32S => todo!(),
            Instruction::I64ExtendI32U => todo!(),
            Instruction::I64TruncF32S => todo!(),
            Instruction::I64TruncF32U => todo!(),
            Instruction::I64TruncF64S => todo!(),
            Instruction::I64TruncF64U => todo!(),
            Instruction::F32ConvertI32S => todo!(),
            Instruction::F32ConvertI32U => todo!(),
            Instruction::F32ConvertI64S => todo!(),
            Instruction::F32ConvertI64U => todo!(),
            Instruction::F32DemoteF64 => todo!(),
            Instruction::F64ConvertI32S => todo!(),
            Instruction::F64ConvertI32U => todo!(),
            Instruction::F64ConvertI64S => todo!(),
            Instruction::F64ConvertI64U => todo!(),
            Instruction::F64PromoteF32 => todo!(),
            Instruction::I32Extend8S => todo!(),
            Instruction::I32Extend16S => todo!(),
            Instruction::I64Extend8S => todo!(),
            Instruction::I64Extend16S => todo!(),
            Instruction::I64Extend32S => todo!(),
            Instruction::I32TruncSatF32S => todo!(),
            Instruction::I32TruncSatF32U => todo!(),
            Instruction::I32TruncSatF64S => todo!(),
            Instruction::I32TruncSatF64U => todo!(),
            Instruction::I64TruncSatF32S => todo!(),
            Instruction::I64TruncSatF32U => todo!(),
            Instruction::I64TruncSatF64S => todo!(),
            Instruction::I64TruncSatF64U => todo!(),
        }

        
    }
}

impl<T> IntoIterator for OpcodeSelectorCols<T> {
    type Item = T;
    type IntoIter = IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        let columns = vec![self.is_alu, self.is_ecall, self.is_auipc, self.is_unimpl,
        self.is_i32add,self.is_i32sub,
        self.is_i32mul,self.is_i32divs,self.is_i32divu,self.is_i32rem,self.is_i32remu,
        self.is_i32lts,self.is_i32ltu,self.is_i32les,self.is_i32leu,
        self.is_i32ges,self.is_i32geu,self.is_i32gts,self.is_i32gtu,
        self.is_i32eq,self.is_i32ne,self.is_i32eqz];
        assert_eq!(columns.len(), NUM_OPCODE_SELECTOR_COLS); 
        columns.into_iter()
    }
}
