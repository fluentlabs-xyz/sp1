#[cfg(test)]
mod tests {

    use crate::rwasmtest::run_rwasm_prover;

    use super::super::*;

    use hashbrown::HashMap;
    use rwasm::engine::Instr;
    use sp1_rwasm_executor::disassembler::binary::{convert_module_to_executable, read_wat, HELLO_PATH, SIMPLE_PATH};
    use sp1_rwasm_executor::{Opcode, Program, SP_START,disassembler::binary::build_rwams_bin};
    use sp1_rwasm_machine::utils::setup_logger;

    use super::super::*;
    use super::*;
    use anyhow::Result;
    use build::try_build_plonk_bn254_artifacts_dev;
    use p3_field::PrimeField32;
    use serde::{Deserialize, Serialize};
    use serial_test::serial;
    use std::fs::File;
    use std::io::{Read, Write};
    use rwasm::engine::bytecode::{BranchOffset, Instruction,DropKeep};
    #[test]
    fn prove_fib(){
        let wasm_bin = read_wat(Path::new(HELLO_PATH));
        let rwasm_module = build_rwams_bin(&wasm_bin);
        let acc_func_section = vec![6,6+19,6+19+3];
        for (ins_idx,item) in rwasm_module.code_section.instr.iter().enumerate(){
            println!(" {item:?}");
            for idx in acc_func_section.iter(){
                if *idx-1==ins_idx as u32{
                    println!("func start,ins_idx:{}",*idx);
                }
            }
        }
       
        let program = convert_module_to_executable(rwasm_module);
        for (ins_idx,item) in program.instructions.iter().enumerate(){
            println!("ins_idx:{},item:{},",ins_idx*4+1,item);
           
        }
        println!("{:?}",program.index_by_offset);
        run_rwasm_prover(program);
    }

    #[test]
    fn prove_simple(){
        let wasm_bin = read_wat(Path::new(SIMPLE_PATH));
        let rwasm_module = build_rwams_bin(&wasm_bin);
        let acc_func_section = vec![6,6+6,6+6+3];
        for (ins_idx,item) in rwasm_module.code_section.instr.iter().enumerate(){
            println!(" {item:?}");
            for idx in acc_func_section.iter(){
                if *idx-1==ins_idx as u32{
                    println!("func start,ins_idx:{}",*idx);
                }
            }
        }
       
        let program = convert_module_to_executable(rwasm_module);
        for (ins_idx,item) in program.instructions.iter().enumerate(){
            println!("ins_idx:{},item:{:?},",ins_idx*4+1,item);
           
        }
        println!("functions: {:?}",program.index_by_offset);
        println!("{:?}",program.index_by_offset);
        run_rwasm_prover(program);
    }
}