

#[cfg(test)]
mod tests {
    #![allow(clippy::print_stdout)]
    use p3_baby_bear::BabyBear;
    use p3_matrix::dense::RowMajorMatrix;
    use rwasm_executor::events::AluEvent;
    use rwasm_executor::{rwasm_ins_to_code, ExecutionRecord, Instruction};
    use rwasm_machine::alu::LtChip;
    use rwasm_machine::utils::{uni_stark_prove, uni_stark_verify};
    use sp1_stark::air::MachineAir;
    use sp1_stark::baby_bear_poseidon2::BabyBearPoseidon2;
    use sp1_stark::{MachineProver, StarkGenericConfig};


    #[test]
    fn generate_trace() {
        let mut shard = ExecutionRecord::default();
        shard.lt_events = vec![AluEvent::new(0, Instruction::I32LtS, 0, 3, 2, rwasm_ins_to_code(Instruction::I32LtS))];
        let chip = LtChip::default();
        let generate_trace = chip.generate_trace(&shard, &mut ExecutionRecord::default());
        let trace: RowMajorMatrix<BabyBear> = generate_trace;
        println!("{:?}", trace.values)
    }

    fn prove_babybear_template(shard: &mut ExecutionRecord) {
        let config = BabyBearPoseidon2::new();
        let mut challenger = config.challenger();

        let chip = LtChip::default();
        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(shard, &mut ExecutionRecord::default());
        let proof = uni_stark_prove::<BabyBearPoseidon2, _>(&config, &chip, &mut challenger, trace);

        let mut challenger = config.challenger();
        uni_stark_verify(&config, &chip, &mut challenger, &proof).unwrap();
    }

    #[test]
    fn prove_babybear_slt() {
        let mut shard = ExecutionRecord::default();

        const NEG_3: u32 = 0b11111111111111111111111111111101;
        const NEG_4: u32 = 0b11111111111111111111111111111100;
        shard.lt_events = vec![
            // 0 == 3 < 2
            AluEvent::new(0, Instruction::I32LtS, 0, 3, 2, rwasm_ins_to_code(Instruction::I32LtS)),
            // 1 == 2 < 3
            AluEvent::new(0, Instruction::I32LtS, 1, 2, 3, rwasm_ins_to_code(Instruction::I32LtS)),
            // 0 == 5 < -3
            AluEvent::new(0, Instruction::I32LtS, 0, 5, NEG_3, rwasm_ins_to_code(Instruction::I32LtS)),
            // 1 == -3 < 5
            AluEvent::new(0, Instruction::I32LtS, 1, NEG_3, 5, rwasm_ins_to_code(Instruction::I32LtS)),
            // 0 == -3 < -4
            AluEvent::new(0, Instruction::I32LtS, 0, NEG_3, NEG_4, rwasm_ins_to_code(Instruction::I32LtS)),
            // 1 == -4 < -3
            AluEvent::new(0, Instruction::I32LtS, 1, NEG_4, NEG_3, rwasm_ins_to_code(Instruction::I32LtS)),
            // 0 == 3 < 3
            AluEvent::new(0, Instruction::I32LtS, 0, 3, 3, rwasm_ins_to_code(Instruction::I32LtS)),
            // 0 == -3 < -3
            AluEvent::new(0, Instruction::I32LtS, 0, NEG_3, NEG_3, rwasm_ins_to_code(Instruction::I32LtS)),
        ];

        prove_babybear_template(&mut shard);
    }

    #[test]
    fn prove_babybear_sltu() {
        let mut shard = ExecutionRecord::default();

        const LARGE: u32 = 0b11111111111111111111111111111101;
        shard.lt_events = vec![
            // 0 == 3 < 2
            AluEvent::new(0, Instruction::I32LtU, 0, 3, 2,rwasm_ins_to_code(Instruction::I32LtU)),
            // 1 == 2 < 3
            AluEvent::new(0, Instruction::I32LtU, 1, 2, 3,rwasm_ins_to_code(Instruction::I32LtU)),
            // 0 == LARGE < 5
            AluEvent::new(0, Instruction::I32LtU, 0, LARGE, 5,rwasm_ins_to_code(Instruction::I32LtU)),
            // 1 == 5 < LARGE
            AluEvent::new(0, Instruction::I32LtU, 1, 5, LARGE,rwasm_ins_to_code(Instruction::I32LtU)),
            // 0 == 0 < 0
            AluEvent::new(0, Instruction::I32LtU, 0, 0, 0,rwasm_ins_to_code(Instruction::I32LtU)),
            // 0 == LARGE < LARGE
            AluEvent::new(0, Instruction::I32LtU, 0, LARGE, LARGE,rwasm_ins_to_code(Instruction::I32LtU)),
        ];

        prove_babybear_template(&mut shard);
    }

    /*
    #[test]
    fn test_malicious_lt() {
        const NUM_TESTS: usize = 5;

        for opcode in [Instruction::I32LtU, Instruction::I32LtS] {
            for _ in 0..NUM_TESTS {
                let op_b = thread_rng().gen_range(0..u32::MAX);
                let op_c = thread_rng().gen_range(0..u32::MAX);

                let correct_op_a = if opcode == Instruction::I32LtU {
                    op_b < op_c
                } else {
                    (op_b as i32) < (op_c as i32)
                };

                let op_a = !correct_op_a;

                let instructions = vec![
                    Instruction::new(opcode, 5, op_b, op_c, true, true),
                    Instruction::new(Instruction::I32Add, 10, 0, 0, false, false),
                ];

                let program = Program::new(instructions, 0, 0);
                let stdin = SP1Stdin::new();

                type P = CpuProver<BabyBearPoseidon2, RwasmAir<BabyBear>>;

                let malicious_trace_pv_generator = move |prover: &P,
                                                         record: &mut ExecutionRecord|
                      -> Vec<(
                          String,
                          RowMajorMatrix<Val>,
                )> {
                    let mut malicious_record = record.clone();
                    malicious_record.cpu_events[0].res = op_a as u32;
                    if let Some(MemoryRecordEnum::Write(mut write_record)) =
                        malicious_record.cpu_events[0].res_record
                    {
                        write_record.value = op_a as u32;
                    }
                    let mut traces = prover.generate_traces(&malicious_record);

                    let lt_chip_name = chip_name!(LtChip, BabyBear);
                    for (chip_name, trace) in traces.iter_mut() {
                        if *chip_name == lt_chip_name {
                            let first_row = trace.row_mut(0);
                            let first_row: &mut LtCols<BabyBear> = first_row.borrow_mut();
                            first_row.a = BabyBear::from_bool(op_a);
                        }
                    }

                    traces
                };

                let result =
                    run_malicious_test::<P>(program, stdin, Box::new(malicious_trace_pv_generator));
                let lt_chip_name = chip_name!(LtChip, BabyBear);
                assert!(
                    result.is_err() && result.unwrap_err().is_constraints_failing(&lt_chip_name)
                );
            }
        }
    }*/
}
