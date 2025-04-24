use std::{hash::Hash, str::FromStr};

use hashbrown::HashMap;
use rwasm::{rwasm::{ InstructionExtra}};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sp1_curves::p256::elliptic_curve::generic_array::arr::Inc;

use crate::{Opcode, RiscvAirId};
type Instruction = rwasm::engine::bytecode::Instruction;
/// Serialize a `HashMap<u32, V>` as a `Vec<(u32, V)>`.
pub fn serialize_hashmap_as_vec<K: Eq + Hash + Serialize, V: Serialize, S: Serializer>(
    map: &HashMap<K, V>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    Serialize::serialize(&map.iter().collect::<Vec<_>>(), serializer)
}

/// Deserialize a `Vec<(u32, V)>` as a `HashMap<u32, V>`.
pub fn deserialize_hashmap_as_vec<
    'de,
    K: Eq + Hash + Deserialize<'de>,
    V: Deserialize<'de>,
    D: Deserializer<'de>,
>(
    deserializer: D,
) -> Result<HashMap<K, V>, D::Error> {
    let seq: Vec<(K, V)> = Deserialize::deserialize(deserializer)?;
    Ok(seq.into_iter().collect())
}

/// Returns `true` if the given `opcode` is a signed operation.
#[must_use]
pub fn is_signed_operation(ins:Instruction) -> bool {
    ins==Instruction::I32DivS || ins ==Instruction::I32RemS
}

/// Calculate the correct `quotient` and `remainder` for the given `b` and `c` per RISC-V spec.
#[must_use]
pub fn get_quotient_and_remainder(b: u32, c: u32, ins:Instruction) -> (u32, u32) {
    if c == 0 {
        // When c is 0, the quotient is 2^32 - 1 and the remainder is b regardless of whether we
        // perform signed or unsigned division.
        (u32::MAX, b)
    } else if is_signed_operation(ins) {
        ((b as i32).wrapping_div(c as i32) as u32, (b as i32).wrapping_rem(c as i32) as u32)
    } else {
        (b.wrapping_div(c), b.wrapping_rem(c))
    }
}

/// Calculate the most significant bit of the given 32-bit integer `a`, and returns it as a u8.
#[must_use]
pub const fn get_msb(a: u32) -> u8 {
    ((a >> 31) & 1) as u8
}

/// Load the cost of each air from the predefined JSON.
#[must_use]
pub fn rv32im_costs() -> HashMap<RiscvAirId, usize> {
    let costs: HashMap<String, usize> =
        serde_json::from_str(include_str!("./artifacts/rv32im_costs.json")).unwrap();
    costs.into_iter().map(|(k, v)| (RiscvAirId::from_str(&k).unwrap(), v)).collect()
}

pub fn rwasm_ins_to_riscv_ins(instruction:Instruction)->Opcode{
   
        match instruction{
            Instruction::I32Add => {
                Opcode::ADD
            },
            Instruction::I32Sub => {
                Opcode::SUB
            }
            Instruction::I32Xor=>Opcode::XOR,
             Instruction::I32Or=>Opcode::OR,
             Instruction::I32And=> {
               Opcode::AND
            }
            Instruction::I32Shl=> {
                Opcode::SLL
            }
            Instruction::I32ShrS =>Opcode::SRA,
             Instruction::I32ShrU => {
                Opcode::SRL
            }
           
            Instruction::I32GeU | Instruction::I32GtU|
            Instruction::I32LeU|Instruction::I32LtU |
            Instruction::I32Eqz   => {
               Opcode::SLTU
            },
            Instruction::I32GeS|
            Instruction::I32GtS|
            Instruction::I32LeS|
            Instruction::I32LeS=>{
                Opcode::SLT
            }

            Instruction::I32Mul  => {
                Opcode::MUL
            },
            Instruction::I32DivS =>{
                Opcode::DIV
            }
            Instruction::I32DivU =>{
                Opcode::DIVU
            }
            Instruction::I32RemS =>{
                Opcode::REM
            }
            Instruction::I32RemU => {
               Opcode::REMU
            }
            Instruction::I32Rotl|Instruction::I32Rotr=>{
                todo!();
            }
            _ => Opcode::UNIMP,
        }
     }


pub fn rwasm_ins_to_code(ins:Instruction)->u32{
    ins.code_value() as u32
}


///  these are psudeo rwasm instruction for chips
pub const I32MULH_CODE:u32=0x0101;
pub const I32MULHU_CODE:u32=0x0102;
pub const I32MULHSU_CODE:u32=0x0102;

