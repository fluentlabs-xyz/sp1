#[cfg(test)]
mod tests {
    #![allow(clippy::print_stdout)]
    use p3_baby_bear::BabyBear;
    use p3_matrix::dense::RowMajorMatrix;
    use rwasm_executor::events::AluEvent;
    use rwasm_executor::{rwasm_ins_to_code, ExecutionRecord, Instruction};
    use rwasm_machine::alu::BitwiseChip;
    use rwasm_machine::utils::{uni_stark_prove, uni_stark_verify};
    use sp1_stark::air::MachineAir;
    use sp1_stark::baby_bear_poseidon2::BabyBearPoseidon2;
    use sp1_stark::StarkGenericConfig;

    #[test]
    fn generate_trace() {
        let mut shard = ExecutionRecord::default();
        shard.bitwise_events = vec![AluEvent::new(
            0,
            Instruction::I32Xor,
            25,
            10,
            19,
            rwasm_ins_to_code(Instruction::I32Xor),
        )];
        let chip = BitwiseChip::default();
        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
        println!("{:?}", trace.values)
    }

    #[test]
    fn prove_babybear() {
        let config = BabyBearPoseidon2::new();
        let mut challenger = config.challenger();

        let mut shard = ExecutionRecord::default();
        shard.bitwise_events = [
            AluEvent::new(
                0,
                Instruction::I32Xor,
                25,
                10,
                19,
                rwasm_ins_to_code(Instruction::I32Xor),
            ),
            AluEvent::new(0, Instruction::I32Or, 27, 10, 19, rwasm_ins_to_code(Instruction::I32Or)),
            AluEvent::new(
                0,
                Instruction::I32And,
                2,
                10,
                19,
                rwasm_ins_to_code(Instruction::I32And),
            ),
        ]
        .repeat(1000);
        let chip = BitwiseChip::default();
        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
        let proof = uni_stark_prove::<BabyBearPoseidon2, _>(&config, &chip, &mut challenger, trace);

        let mut challenger = config.challenger();
        let result = uni_stark_verify(&config, &chip, &mut challenger, &proof).unwrap();
        println!("{:?}", result);
    }
}
