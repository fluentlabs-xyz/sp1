use hashbrown::HashMap;
use rwasm::engine::Instr;
use rwasm_executor::{Opcode, Program, SP_START};
use rwasm_machine::utils::setup_logger;

use super::*;
use anyhow::Result;
use build::try_build_plonk_bn254_artifacts_dev;
use p3_field::PrimeField32;
use serde::{Deserialize, Serialize};
use serial_test::serial;
use std::fs::File;
use std::io::{Read, Write};

pub fn run_rwasm_prover(mut program: Program) {
    setup_logger();
    let prover: SP1Prover = SP1Prover::new();
    let mut opts = SP1ProverOpts::default();
    opts.core_opts.shard_batch_size = 1;
    let context = SP1Context::default();

    tracing::info!("setup elf");
    let (_, pk, vk) = prover.setup_program(&mut program);

    tracing::info!("prove core");
    let stdin = SP1Stdin::new();
    let core_proof = prover.prove_core(&pk, program.clone(), &stdin, opts, context);
    tracing::info!("prove core finish");
    match core_proof {
        Ok(_) => {
            tracing::info!("verify core");
            prover.verify(&core_proof.unwrap().proof, &vk).unwrap();
        }
        Err(err) => {
            println!("{}", err);
        }
    }

    println!("done rwasm proof");
}
#[cfg(test)]
mod tests {

    use super::super::*;

    use hashbrown::HashMap;
    use rwasm::engine::Instr;
    use rwasm_executor::{Opcode, Program, SP_START};
    use rwasm_machine::utils::setup_logger;

    use super::super::*;
    use super::*;
    use anyhow::Result;
    use build::try_build_plonk_bn254_artifacts_dev;
    use p3_field::PrimeField32;
    use serde::{Deserialize, Serialize};
    use serial_test::serial;
    use std::fs::File;
    use std::io::{Read, Write};

    use rwasm::engine::bytecode::{BranchOffset, DropKeep, Instruction};
    fn build_elf() -> Program {
        let x_value: u32 = 0x11;
        let y_value: u32 = 0x23;
        let z1_value: u32 = 0x40;
        let z2_value: u32 = 0x37;
        let z3_value: u32 = 0x1800;
        let z4_value: u32 = 0x2;
        let z5_value: u32 = 0x7;
        let z6_value: u32 = 0x21;

        let instructions = vec![
            Instruction::I32Const(z6_value.into()),
            Instruction::I32Const(z5_value.into()),
            Instruction::I32Const(z4_value.into()),
            Instruction::I32Const(z3_value.into()),
            Instruction::I32Const(z2_value.into()),
            Instruction::I32Const(z1_value.into()),
            Instruction::I32Const(y_value.into()),
            Instruction::I32Const(x_value.into()),
            Instruction::I32Add,
            Instruction::I32Sub,
            Instruction::I32Mul,
            Instruction::I32DivS,
            Instruction::I32DivU,
        ];

        let program = Program::new_with_memory(instructions, HashMap::new(), 1, 1);
        //  memory_image: BTreeMap::new() };

        program
    }

    fn build_elf2() -> Program {
        let x_value: u32 = 0x11;
        let y_value: u32 = 0x23;
        let z1_value: u32 = 0x3;
        let z2_value: u32 = 0x37;
        let z3_value: u32 = 0x12;
        let z4_value: u32 = 0x2;
        let z5_value: u32 = 0x7;
        let z6_value: u32 = 0x21;
        let z7_value: u32 = 0x333333;
        let z8_value: u32 = 0x444444;

        let instructions = vec![
            Instruction::I32Const(x_value.into()),
            Instruction::I32Const(y_value.into()),
            Instruction::I32Const(z1_value.into()),
            Instruction::I32Const(z2_value.into()),
            Instruction::I32Const(z3_value.into()),
            Instruction::I32Const(z4_value.into()),
            Instruction::I32Const(z5_value.into()),
            Instruction::I32Const(z6_value.into()),
            Instruction::I32Const(z7_value.into()),
            Instruction::I32Const(z8_value.into()),
            Instruction::I32Ne,
            Instruction::I32Eq,
            Instruction::I32GtS,
            Instruction::I32GtU,
            Instruction::I32LeS,
            Instruction::I32LeU,
            Instruction::I32GeS,
            Instruction::I32GeU,
            Instruction::I32LtS,
            Instruction::I32Eqz,
        ];

        let program = Program::new_with_memory(instructions, HashMap::new(), 1, 1);
        //  memory_image: BTreeMap::new() };

        program
    }

    fn build_elf3() -> Program {
        let x_value: u32 = 0x1;
        let y_value: u32 = 0x2;
        let z1_value: u32 = 0x1;
        let z2_value: u32 = 0x2;
        let z3_value: u32 = 0x1;
        let z4_value: u32 = 0x2;
        let z5_value: u32 = 0x1;

        let instructions = vec![
            Instruction::I32Const(x_value.into()),
            Instruction::I32Const(y_value.into()),
            Instruction::I32Const(z1_value.into()),
            Instruction::I32Const(z2_value.into()),
            Instruction::I32Const(z3_value.into()),
            Instruction::I32Const(z4_value.into()),
            Instruction::I32Const(z5_value.into()),
            Instruction::I32And,
            Instruction::I32Or,
            Instruction::I32Xor,
            Instruction::I32Shl,
            Instruction::I32ShrS,
            Instruction::I32ShrU,
        ];
        let program = Program::new_with_memory(instructions, HashMap::new(), 1, 1);
        program
    }

    fn build_elf4() -> Program {
        let sp_value: u32 = SP_START;
        let addr: u32 = 0x10000;
        let addr_2: u32 = 0x10004;
        let addr_3: u32 = 0x10008;
        let addr_4: u32 = 0x1000C;
        let addr_5: u32 = 0x10010;
        let x_value: u32 = 0x10004;
        let x_2_value: u32 = 0x10008;
        let x_3_value: u32 = 0x1000C;

        let mut mem = HashMap::new();
        mem.insert(sp_value, addr);
        mem.insert(sp_value - 4, addr_2);
        mem.insert(sp_value - 8, 0x10000);
        mem.insert(sp_value - 12, addr_3);
        mem.insert(sp_value - 16, 0x10000);
        mem.insert(addr, x_value);
        mem.insert(addr_2, x_2_value);
        mem.insert(addr_3, x_3_value);

        println!("{:?}", mem);
        let instructions = vec![
            Instruction::I32Load(0.into()),
            Instruction::I32Load16U(0.into()),
            Instruction::I32Add,
            Instruction::I32Load8U(0x10000.into()),
            Instruction::I32Add,
            Instruction::I32Load16S(0.into()),
            Instruction::I32Load8S(0.into()),
        ];

        let program = Program::new_with_memory(instructions, mem, 1, 1);
        //  memory_image: BTreeMap::new() };

        program
    }

    fn build_elf5() -> Program {
        let addr: u32 = 0x10000;
        let addr_2: u32 = 0x10004;
        let addr_3: u32 = 0x10008;

        let x_value: u32 = 0x10007;
        let x_2_value: u32 = 0x10008;

        let x_3_value: u32 = 0x1000C;

        let instructions = vec![
            Instruction::I32Const(x_3_value.into()),
            Instruction::I32Const(addr_3.into()),
            Instruction::I32Const(x_2_value.into()),
            Instruction::I32Const(addr_2.into()),
            Instruction::I32Const(addr.into()),
            Instruction::I32Const(x_value.into()),
            Instruction::I32Store(0.into()),
            Instruction::I32Store16(0.into()),
            Instruction::I32Store8(0.into()),
        ];

        let program = Program::new_with_memory(instructions, HashMap::new(), 1, 1);
        //  memory_image: BTreeMap::new() };

        program
    }
    fn build_elf_br() -> Program {
        let x_value: u32 = 0x1;
        let addr: u32 = 0x10000;

        let instructions = vec![
            Instruction::I32Const(x_value.into()),
            Instruction::I32Const(x_value.into()),
            Instruction::I32Const(x_value.into()),
            Instruction::I32Const(x_value.into()),
            Instruction::Br(4.into()),
            Instruction::I32Shl,
            Instruction::I32Shl,
            Instruction::I32Shl,
        ];

        let program = Program::new_with_memory(instructions, HashMap::new(), 1, 1);
        program
    }

    fn build_elf_branching() -> Program {
        let sp_value: u32 = SP_START;
        let x_value: u32 = 0x0;
        let x_2_value: u32 = 0x10008;
        let x_3_value: u32 = 0x1000C;

        let mut mem = HashMap::new();
        mem.insert(sp_value, x_value);
        mem.insert(sp_value - 4, x_2_value);
        mem.insert(sp_value - 8, x_3_value);

        println!("{:?}", mem);
        let instructions = vec![
            Instruction::Br(20.into()),
            Instruction::I32Add,
            Instruction::I32Add,
            Instruction::I32Add,
            Instruction::BrIfNez(12.into()),
            Instruction::I32Add,
            Instruction::BrIfNez(BranchOffset::from(-8i32)),
            Instruction::I32Add,
        ];

        let program = Program::new_with_memory(instructions, mem, 1, 1);
        //  memory_image: BTreeMap::new() };

        program
    }

    fn build_elf_local_const() -> Program {
        let sp_value: u32 = SP_START;
        let x_value: u32 = 0x1234;
        let x_2_value: u32 = x_value + 5;
        let depth = 5 * 4;
        let under_depth = depth - 4;
        let constant = x_value;
        let mut mem = HashMap::new();
        mem.insert(sp_value, x_value);
        mem.insert(sp_value - depth, x_2_value);

        println!("{:?}", mem);
        let instructions = vec![
            Instruction::LocalGet(depth.into()),
            Instruction::LocalSet(under_depth.into()),
            Instruction::LocalTee(under_depth.into()),
            Instruction::I32Const(constant.into()),
        ];

        let program = Program::new_with_memory(instructions, mem, 1, 1);
        //  memory_image: BTreeMap::new() };

        program
    }
    fn build_elf_const_another() -> Program {
        let sp_value: u32 = SP_START;
        let x_value: u32 = 0x12345;
        let y_value: u32 = 0x54321;
        let mut mem = HashMap::new();

        println!("{:?}", mem);
        let instructions = vec![
            Instruction::I32Const(x_value.into()),
            Instruction::I32Const(y_value.into()),
            Instruction::I32Add,
        ];

        let program = Program::new_with_memory(instructions, mem, 1, 1);
        //  memory_image: BTreeMap::new() };

        program
    }
    fn build_elf_call() -> Program {
        let sp_value: u32 = SP_START;
        let x_value: u32 = 0x3;
        let y_value: u32 = 0x5;

        let mut mem = HashMap::new();
        mem.insert(sp_value, x_value);
        mem.insert(sp_value - 4, y_value);
        let mut functions = vec![12 + 1];

        let instructions = vec![
            Instruction::CallInternal(1u32.into()),
            Instruction::Return(DropKeep::none()),
            Instruction::I32Add,
            Instruction::Return(DropKeep::none()),
        ];

        let program = Program::new_with_memory_and_func(instructions, mem, functions, 1, 1);
        program
    }
    fn build_elf_call2() -> Program {
        let sp_value: u32 = SP_START;
        let x_value: u32 = 0x3;
        let y_value: u32 = 0x5;
        let z_value: u32 = 0x7;
        let mut mem = HashMap::new();

        let mut functions = vec![21];

        let instructions = vec![
            Instruction::I32Const(x_value.into()),
            Instruction::I32Const(y_value.into()),
            Instruction::I32Const(z_value.into()),
            Instruction::CallInternal(0u32.into()),
            Instruction::Return(DropKeep::none()),
            Instruction::I32Add,
            Instruction::I32Add,
            Instruction::Return(DropKeep::none()),
        ];

        let program = Program::new_with_memory_and_func(instructions, mem, functions.clone(), 1, 1);
        for (ins_idx, item) in program.instructions.iter().enumerate() {
            println!("ins_idx:{},item:{:?},", ins_idx * 4 + 1, item);
        }
        println!("functions: {:?}", functions);
        program
    }

    fn build_elf_call3() -> Program {
        let sp_value: u32 = SP_START;
        let x_value: u32 = 0x3;
        let y_value: u32 = 0x5;
        let z_value: u32 = 0x7;
        let mut mem = HashMap::new();

        let mut functions = vec![13, 17, 25];

        let instructions = vec![
            Instruction::I32Const(x_value.into()),
            Instruction::CallInternal(1u32.into()),
            Instruction::Return(DropKeep::none()),
            Instruction::Return(DropKeep::none()),
            Instruction::CallInternal(0u32.into()),
            Instruction::Return(DropKeep::none()),
        ];

        let program = Program::new_with_memory_and_func(instructions, mem, functions.clone(), 1, 1);
        for (ins_idx, item) in program.instructions.iter().enumerate() {
            println!("ins_idx:{},item:{:?},", ins_idx * 4 + 1, item);
        }
        println!("functions: {:?}", functions);
        program
    }

    fn build_elf_skipped_ins() -> Program {
        let sp_value: u32 = SP_START;
        let x_value: u32 = 0x1234;
        let x_2_value: u32 = x_value + 5;
        let depth = 5 * 4;
        let under_depth = depth - 4;
        let constant = x_value;
        let mut mem = HashMap::new();
        mem.insert(sp_value, x_value);
        mem.insert(sp_value - depth, x_2_value);

        println!("{:?}", mem);
        let instructions = vec![
            Instruction::ConsumeFuel(1.into()),
            Instruction::SignatureCheck(1.into()),
            Instruction::Drop,
        ];

        let program = Program::new_with_memory(instructions, mem, 1, 1);
        //  memory_image: BTreeMap::new() };

        program
    }

    #[test]
    fn test_rwasm_proof1() {
        let program = build_elf();
        run_rwasm_prover(program);
    }
    #[test]
    fn test_rwasm_proof2() {
        let program = build_elf2();
        run_rwasm_prover(program);
    }
    #[test]
    fn test_rwasm_proof3() {
        let program = build_elf3();
        run_rwasm_prover(program);
    }
    #[test]
    fn test_rwasm_proof4() {
        let program = build_elf4();
        run_rwasm_prover(program);
    }
    #[test]
    fn test_rwasm_proof5() {
        let program = build_elf5();
        run_rwasm_prover(program);
    }
    #[test]
    fn test_rwasm_br() {
        let program = build_elf_br();
        run_rwasm_prover(program);
    }
    #[test]
    fn test_rwasm_branching() {
        let program = build_elf_branching();
        run_rwasm_prover(program);
    }

    #[test]
    fn test_rwasm_local() {
        let program = build_elf_local_const();
        run_rwasm_prover(program);
    }

    #[test]
    fn test_rwasm_another1() {
        let program = build_elf_const_another();
        run_rwasm_prover(program);
    }
    #[test]
    fn test_rwasm_call_internal_and_return() {
        let program = build_elf_call();
        run_rwasm_prover(program);
    }
    #[test]
    fn test_rwasm_call_internal_and_return2() {
        let program = build_elf_call2();
        run_rwasm_prover(program);
    }

    #[test]
    fn test_rwasm_call_internal_and_return3() {
        let program = build_elf_call3();
        run_rwasm_prover(program);
    }

    #[test]
    fn test_rwasm_skipped() {
        let program = build_elf_skipped_ins();
        run_rwasm_prover(program);
    }
}
