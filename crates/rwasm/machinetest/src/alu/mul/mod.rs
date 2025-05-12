#[cfg(test)]
mod tests {

    #![allow(clippy::print_stdout)]
    use p3_baby_bear::BabyBear;
    use p3_matrix::dense::RowMajorMatrix;
    use rand::{thread_rng, Rng};
    use rwasm_executor::events::{AluEvent, MemoryRecordEnum};
    use rwasm_executor::{rwasm_ins_to_code, ExecutionRecord, Instruction, Program};
    use rwasm_machine::alu::{LtChip, MulChip};
    use rwasm_machine::io::SP1Stdin;
    use rwasm_machine::rwasm::RwasmAir;
    use rwasm_machine::utils::{
        run_malicious_test, uni_stark_prove as prove, uni_stark_verify as verify,
    };
    use sp1_stark::air::MachineAir;
    use sp1_stark::baby_bear_poseidon2::BabyBearPoseidon2;
    use sp1_stark::{chip_name, CpuProver, MachineProver, StarkGenericConfig, Val};

    #[test]
    fn generate_trace_mul() {
        let mut shard = ExecutionRecord::default();

        // Fill mul_events with 10^7 MULHSU events.
        let mut mul_events: Vec<AluEvent> = Vec::new();
        for _ in 0..10i32.pow(7) {
            mul_events.push(AluEvent::new(
                0,
                Instruction::I32Mul,
                0x80004000,
                0x80000000,
                0xffff8000,
                rwasm_ins_to_code(Instruction::I32Mul),
            ));
        }
        shard.mul_events = mul_events;
        let chip = MulChip::default();
        let _trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
    }

    #[test]
    fn prove_babybear() {
        let config = BabyBearPoseidon2::new();
        let mut challenger = config.challenger();

        let mut shard = ExecutionRecord::default();
        let mut mul_events: Vec<AluEvent> = Vec::new();

        let mul_instructions: Vec<(Instruction, u32, u32, u32)> = vec![
            (Instruction::I32Mul, 0x00001200, 0x00007e00, 0xb6db6db7),
            (Instruction::I32Mul, 0x00001240, 0x00007fc0, 0xb6db6db7),
            (Instruction::I32Mul, 0x00000000, 0x00000000, 0x00000000),
            (Instruction::I32Mul, 0x00000001, 0x00000001, 0x00000001),
            (Instruction::I32Mul, 0x00000015, 0x00000003, 0x00000007),
            (Instruction::I32Mul, 0x00000000, 0x00000000, 0xffff8000),
            (Instruction::I32Mul, 0x00000000, 0x80000000, 0x00000000),
            (Instruction::I32Mul, 0x00000000, 0x80000000, 0xffff8000),
            (Instruction::I32Mul, 0x0000ff7f, 0xaaaaaaab, 0x0002fe7d),
            (Instruction::I32Mul, 0x0000ff7f, 0x0002fe7d, 0xaaaaaaab),
            (Instruction::I32Mul, 0x00000000, 0xff000000, 0xff000000),
            (Instruction::I32Mul, 0x00000001, 0xffffffff, 0xffffffff),
            (Instruction::I32Mul, 0xffffffff, 0xffffffff, 0x00000001),
            (Instruction::I32Mul, 0xffffffff, 0x00000001, 0xffffffff),
            (Instruction::I32Mul, 0x00000000, 0x00000000, 0x00000000),
            (Instruction::I32Mul, 0x00000000, 0x00000001, 0x00000001),
            (Instruction::I32Mul, 0x00000000, 0x00000003, 0x00000007),
            (Instruction::I32Mul, 0x00000000, 0x00000000, 0xffff8000),
            (Instruction::I32Mul, 0x00000000, 0x80000000, 0x00000000),
            (Instruction::I32Mul, 0x7fffc000, 0x80000000, 0xffff8000),
            (Instruction::I32Mul, 0x0001fefe, 0xaaaaaaab, 0x0002fe7d),
            (Instruction::I32Mul, 0x0001fefe, 0x0002fe7d, 0xaaaaaaab),
            (Instruction::I32Mul, 0xfe010000, 0xff000000, 0xff000000),
            (Instruction::I32Mul, 0xfffffffe, 0xffffffff, 0xffffffff),
            (Instruction::I32Mul, 0x00000000, 0xffffffff, 0x00000001),
            (Instruction::I32Mul, 0x00000000, 0x00000001, 0xffffffff),
            (Instruction::I32Mul, 0x00000000, 0x00000000, 0x00000000),
            (Instruction::I32Mul, 0x00000000, 0x00000001, 0x00000001),
            (Instruction::I32Mul, 0x00000000, 0x00000003, 0x00000007),
            (Instruction::I32Mul, 0x00000000, 0x00000000, 0xffff8000),
            (Instruction::I32Mul, 0x00000000, 0x80000000, 0x00000000),
            (Instruction::I32Mul, 0x80004000, 0x80000000, 0xffff8000),
            (Instruction::I32Mul, 0xffff0081, 0xaaaaaaab, 0x0002fe7d),
            (Instruction::I32Mul, 0x0001fefe, 0x0002fe7d, 0xaaaaaaab),
            (Instruction::I32Mul, 0xff010000, 0xff000000, 0xff000000),
            (Instruction::I32Mul, 0xffffffff, 0xffffffff, 0xffffffff),
            (Instruction::I32Mul, 0xffffffff, 0xffffffff, 0x00000001),
            (Instruction::I32Mul, 0x00000000, 0x00000001, 0xffffffff),
            (Instruction::I32Mul, 0x00000000, 0x00000000, 0x00000000),
            (Instruction::I32Mul, 0x00000000, 0x00000001, 0x00000001),
            (Instruction::I32Mul, 0x00000000, 0x00000003, 0x00000007),
            (Instruction::I32Mul, 0x00000000, 0x00000000, 0xffff8000),
            (Instruction::I32Mul, 0x00000000, 0x80000000, 0x00000000),
            (Instruction::I32Mul, 0x00000000, 0x80000000, 0x00000000),
            (Instruction::I32Mul, 0xffff0081, 0xaaaaaaab, 0x0002fe7d),
            (Instruction::I32Mul, 0xffff0081, 0x0002fe7d, 0xaaaaaaab),
            (Instruction::I32Mul, 0x00010000, 0xff000000, 0xff000000),
            (Instruction::I32Mul, 0x00000000, 0xffffffff, 0xffffffff),
            (Instruction::I32Mul, 0xffffffff, 0xffffffff, 0x00000001),
            (Instruction::I32Mul, 0xffffffff, 0x00000001, 0xffffffff),
        ];
        for t in mul_instructions.iter() {
            mul_events.push(AluEvent::new(0, t.0, t.1, t.2, t.3, rwasm_ins_to_code(t.0)));
        }

        // Append more events until we have 1000 tests.
        for _ in 0..(1000 - mul_instructions.len()) {
            mul_events.push(AluEvent::new(
                0,
                Instruction::I32Mul,
                1,
                1,
                1,
                rwasm_ins_to_code(Instruction::I32Mul),
            ));
        }

        shard.mul_events = mul_events;
        let chip = MulChip::default();
        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
        let proof = prove::<BabyBearPoseidon2, _>(&config, &chip, &mut challenger, trace);

        let mut challenger = config.challenger();
        verify(&config, &chip, &mut challenger, &proof).unwrap();
    }

    /* #[test]
    fn test_malicious_mul() {
        const NUM_TESTS: usize = 5;

        for opcode in [Instruction::I32Mul, Instruction::I32Mul, Instruction::I32Mul, Instruction::I32Mul] {
            for _ in 0..NUM_TESTS {
                let (correct_op_a, op_b, op_c) = if opcode == Instruction::I32Mul {
                    let op_b = thread_rng().gen_range(0..i32::MAX);
                    let op_c = thread_rng().gen_range(0..i32::MAX);
                    ((op_b.overflowing_mul(op_c).0) as u32, op_b as u32, op_c as u32)
                } else if opcode == Instruction::I32Mul {
                    let op_b = thread_rng().gen_range(0..i32::MAX);
                    let op_c = thread_rng().gen_range(0..i32::MAX);
                    let result = (op_b as i64) * (op_c as i64);
                    (((result >> 32) as i32) as u32, op_b as u32, op_c as u32)
                } else if opcode == Instruction::I32Mul {
                    let op_b = thread_rng().gen_range(0..u32::MAX);
                    let op_c = thread_rng().gen_range(0..u32::MAX);
                    let result: u64 = (op_b as u64) * (op_c as u64);
                    ((result >> 32) as u32, op_b as u32, op_c as u32)
                } else if opcode == Instruction::I32Mul {
                    let op_b = thread_rng().gen_range(0..i32::MAX);
                    let op_c = thread_rng().gen_range(0..u32::MAX);
                    let result: i64 = (op_b as i64) * (op_c as i64);
                    ((result >> 32) as u32, op_b as u32, op_c as u32)
                } else {
                    unreachable!()
                };

                let op_a = thread_rng().gen_range(0..u32::MAX);
                assert!(op_a != correct_op_a);

                let instructions = vec![
                    Instruction::new(opcode, 5, op_b, op_c, true, true),
                    Instruction::new(Opcode::ADD, 10, 0, 0, false, false),
                ];

                let program = Program::new(instructions, 0, 0);
                let stdin = SP1Stdin::new();

                type P = CpuProver<BabyBearPoseidon2, RwasmAir<BabyBear>>;

                let malicious_trace_pv_generator = move |prover: &P,
                                                         record: &mut ExecutionRecord|
                      -> Vec<(
                    String,
                    RowMajorMatrix<Val<BabyBearPoseidon2>>,
                )> {
                    let mut malicious_record = record.clone();
                    malicious_record.cpu_events[0].res = op_a as u32;
                    if let Some(MemoryRecordEnum::Write(mut write_record)) =
                        malicious_record.cpu_events[0].res_record
                    {
                        write_record.value = op_a as u32;
                    }
                    malicious_record.mul_events[0].a = op_a;
                    prover.generate_traces(&malicious_record)
                };

                let result =
                    run_malicious_test::<P>(program, stdin, Box::new(malicious_trace_pv_generator));
                let mul_chip_name = chip_name!(MulChip, BabyBear);
                assert!(
                    result.is_err() && result.unwrap_err().is_constraints_failing(&mul_chip_name)
                );
            }
        }
    }*/
}
