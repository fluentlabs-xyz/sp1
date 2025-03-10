use std::{fs, path::Path};

use hashbrown::HashMap;
use log::debug;
use rwasm::engine::bytecode::Instruction;
use rwasm::rwasm::{InstructionExtra, RwasmModule};
use rwasm::rwasm::{BinaryFormat};
use rwasm::Engine;

use crate::{program, Program};

const FIB_PATH :&str = "../examples/fib/fibonacci.wat";
const HELLO_PATH :&str = "../examples/hello/hello.wat";
fn read_wat(file:&Path)->Vec<u8>{
    let file_bytes = fs::read(file).unwrap();
    let wasm_binary: Vec<u8>;
    
        wasm_binary = wat::parse_bytes(&file_bytes).unwrap().to_vec();
        
        wasm_binary
}

pub (crate) fn build_rwams_bin(wasm_bin:&Vec<u8>)->RwasmModule{
    let config = RwasmModule::default_config(None);
   
    // compile rWASM module from WASM binary
    let rwasm_module = RwasmModule::compile_with_config(&wasm_bin, &config).unwrap();
    // lets encode/decode rWASM module
    let mut encoded_rwasm_module = Vec::new();
    rwasm_module
        .write_binary_to_vec(&mut encoded_rwasm_module)
        .unwrap();
   rwasm_module
    
}
/*

Currently missing Instruction:
ConsumeFuel
SignatureCheck
Drop
 */
 
pub (crate)  fn convert_module_to_executable(rwasm_module:RwasmModule)->Program{
    let rwasm_instr :Vec<Instruction>= rwasm_module.code_section.instr.clone();
    let mut instr_vec = rwasm_instr.clone();
    for x in instr_vec.iter_mut(){
        match x {
            Instruction::BrIfEqz(_)=>{
                let aux_val:i32 = x.aux_value().unwrap().as_i32();
                *x=Instruction::BrIfEqz((aux_val*4).into());
            },
            _=>()
        }
    };
   
    let mut func_indices =  rwasm_module.func_section.clone();
   
    let mut acc = 0;
    for x in &mut func_indices {
        acc += (*x *4) as i32;
        *x = (acc+1) as u32;
    }
    // let mut head = vec![0u32];
    // head.append(&mut func_indices);
    // func_indices =head;
   let program=Program::new_with_memory_and_func(instr_vec,HashMap::new(),func_indices, 1, 1);
   program
} 

mod test{
    use std::{fs, path::Path};

use log::debug;
use rwasm::rwasm::RwasmModule;
use rwasm::rwasm::{BinaryFormat};
use rwasm::Engine;
use sp1_stark::SP1CoreOpts;
    
    use crate::Executor;

    use super::*;
    #[test]
    fn test_rwasm_fib(){
        println!("{:?}",std::env::current_dir());
        let wasm_bin = read_wat(Path::new(FIB_PATH));
        let rwasm_module = build_rwams_bin(&wasm_bin);
        
        println!("{:?}",rwasm_module);
    }
    #[test]
    fn test_rwasm_hello(){
        println!("{:?}",std::env::current_dir());
        let wasm_bin = read_wat(Path::new(HELLO_PATH));
        let rwasm_module = build_rwams_bin(&wasm_bin);
        println!("code section:\n");
        let acc_func_section = vec![6,6+19,6+19+3];
        for (ins_idx,item) in rwasm_module.code_section.instr.iter().enumerate(){
            println!(" {item:?}");
            for idx in acc_func_section.iter(){
                if *idx-1==ins_idx as u32{
                    println!("func start,ins_idx:{}",*idx);
                }
            }
        }
       
        println!("func_section : {:?}",rwasm_module.func_section);
        println!("memory_section): {:?}",rwasm_module.memory_section);
        println!("{:?}",rwasm_module.element_section);
        let program = convert_module_to_executable(rwasm_module);
        for item in program.instructions.iter(){
            println!("{:?}",item);
        }
        println!("{:?}",program.index_by_offset);
    }
    #[test]
    fn test_execute_binary(){
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
        let mut runtime = Executor::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        for event in runtime.records[0].cpu_events.iter(){
            println!("event:{:?}",event);
        }
        
    }
}