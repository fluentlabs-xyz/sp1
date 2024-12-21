use sp1_rwasm_executor::{Opcode};
use rwasm::engine::bytecode::Instruction;

pub fn rwasm_ins_to_sp1_alu(ins:&Instruction)->Opcode{
    match ins{
        Instruction::I32Add=>{
            Opcode::ADD
        },
        Instruction::I32Sub=>{
            Opcode::SUB
        },
        Instruction::I32Mul=>{
            Opcode::MUL
        },
        Instruction::I32DivS=>{
            Opcode::DIV
        },
        Instruction::I32DivU=>{
            Opcode::DIVU
        },


        _=>{todo!()}
    }
}