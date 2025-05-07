

#[cfg(test)]
pub mod test {

    #![allow(clippy::print_stdout)]

    use p3_baby_bear::BabyBear;
    use p3_matrix::dense::RowMajorMatrix;
    use rand::{thread_rng, Rng};
    use rwasm_executor::{events::AluEvent, rwasm_ins_to_code, ExecutionRecord, Instruction, Opcode, DEFAULT_PC_INC};
    use rwasm_machine::rwasm::AddSubChip;
    use sp1_stark::{air::MachineAir, MachineProver, StarkGenericConfig};
    use std::sync::LazyLock;
    use rwasm_machine::utils::{uni_stark_prove, uni_stark_verify};
    use sp1_stark::baby_bear_poseidon2::BabyBearPoseidon2;

    #[test]
    fn generate_trace() {
        let mut shard = ExecutionRecord::default();
        shard.add_events = vec![AluEvent::new(0, Instruction::I32Add, 14, 8, 6,rwasm_ins_to_code(Instruction::I32Add))];
        let chip = AddSubChip::default();
        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
        println!("{:?}", trace.values)
    }

    
    #[test]
    fn prove_babybear() {
        let config = BabyBearPoseidon2::new();
        let mut challenger = config.challenger();

        let mut shard = ExecutionRecord::default();
        for i in 0..1 {
            let operand_1 = thread_rng().gen_range(0..100u32);
            let operand_2 = thread_rng().gen_range(0..100u32);
            let result = operand_1.wrapping_add(operand_2).wrapping_add(operand_2);
            println!("{},{},{}",operand_1,operand_2,result);
            shard.add_events.push(AluEvent::new(
                i * DEFAULT_PC_INC,
                Instruction::I32Add,
                result,
                operand_1,
                operand_2,
                rwasm_ins_to_code(Instruction::I32Add),
            ));
        }
        // for i in 0..255 {
        //     let operand_1 = thread_rng().gen_range(0..u32::MAX);
        //     let operand_2 = thread_rng().gen_range(0..u32::MAX);
        //     let result = operand_1.wrapping_sub(operand_2);
        //     shard.add_events.push(AluEvent::new(
        //         i * DEFAULT_PC_INC,
        //         Instruction::I32Sub,
        //         result,
        //         operand_1,
        //         operand_2,
        //         rwasm_ins_to_code(Instruction::I32Sub),
        //     ));
        // }

        let chip = AddSubChip::default();
        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
        let proof = uni_stark_prove::<BabyBearPoseidon2, _>(&config, &chip, &mut challenger, trace);

        let mut challenger = config.challenger();
        let result = uni_stark_verify(&config, &chip, &mut challenger, &proof).unwrap();
        println!("{:?}", result);
    }

}
