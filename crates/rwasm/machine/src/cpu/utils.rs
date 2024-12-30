use sp1_rwasm_executor::{Opcode};
use rwasm::engine::bytecode::Instruction;

pub fn rwasm_ins_to_sp1_alu(ins:&Instruction)->Option<Opcode>{
    match ins{
        Instruction::I32Add=>{
            Some(Opcode::ADD)
        },
        Instruction::I32Sub=>{
           Some( Opcode::SUB)
        },
        Instruction::I32Mul=>{
            Some(Opcode::MUL)
        },
        Instruction::I32DivS=>{
            Some(Opcode::DIV)
        },
        Instruction::I32DivU=>{
            Some(Opcode::DIVU)
        },
        Instruction::I32RemU=>{
            Some(Opcode::REMU)
        },
        Instruction::I32RemS=>{
            Some(Opcode::REM)
        },
        Instruction::I32LtS=>{
            Some(Opcode::SLT)
        },
        Instruction::I32LtU=>{
            Some(Opcode::SLTU)
        }
         _=>{None}
    }
}