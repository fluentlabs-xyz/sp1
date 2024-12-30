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
        Instruction::I32And=>{
            Some(Opcode::AND)
        },
        Instruction::I32Or=>{
            Some(Opcode::OR)
        },
        Instruction::I32Xor=>{
            Some(Opcode::XOR)
        },
        Instruction::I32Shl=>{
            Some(Opcode::SLL)
        },
        Instruction::I32ShrS=>{
            Some(Opcode::SRA)
        },
        Instruction::I32ShrU=>{
            Some(Opcode::SRL)
        },
        
         _=>{None}
    }
}