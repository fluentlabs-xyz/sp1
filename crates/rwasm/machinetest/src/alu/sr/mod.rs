

#[cfg(test)]
mod tests {
    #![allow(clippy::print_stdout)]

    use p3_baby_bear::BabyBear;
    use p3_matrix::dense::RowMajorMatrix;
    use rand::{thread_rng, Rng};
    use rwasm_executor::events::{AluEvent, MemoryRecordEnum};
    use rwasm_executor::{rwasm_ins_to_code, ExecutionRecord, Instruction, Program};
    use rwasm_machine::alu::{LtChip, MulChip, ShiftLeft, ShiftLeftCols, ShiftRightChip};
    use rwasm_machine::io::SP1Stdin;
    use rwasm_machine::rwasm::RwasmAir;
    use rwasm_machine::utils::{
        run_malicious_test, uni_stark_prove as prove, uni_stark_verify as verify,
    };
    use sp1_stark::air::MachineAir;
    use sp1_stark::baby_bear_poseidon2::BabyBearPoseidon2;
    use sp1_stark::{chip_name, CpuProver, MachineProver, StarkGenericConfig, Val};
 
    #[test]
    fn generate_trace() {
        let mut shard = ExecutionRecord::default();
        shard.shift_right_events = vec![AluEvent::new(0, Instruction::I32ShrU, 6, 12, 1, rwasm_ins_to_code(Instruction::I32ShrU))];
        let chip = ShiftRightChip::default();
        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
        println!("{:?}", trace.values)
    }

    #[test]
    fn prove_babybear() {
        let config = BabyBearPoseidon2::new();
        let mut challenger = config.challenger();

        let shifts = vec![
            (Instruction::I32ShrU, 0xffff8000, 0xffff8000, 0),
            (Instruction::I32ShrU, 0x7fffc000, 0xffff8000, 1),
            (Instruction::I32ShrU, 0x01ffff00, 0xffff8000, 7),
            (Instruction::I32ShrU, 0x0003fffe, 0xffff8000, 14),
            (Instruction::I32ShrU, 0x0001ffff, 0xffff8001, 15),
            (Instruction::I32ShrU, 0xffffffff, 0xffffffff, 0),
            (Instruction::I32ShrU, 0x7fffffff, 0xffffffff, 1),
            (Instruction::I32ShrU, 0x01ffffff, 0xffffffff, 7),
            (Instruction::I32ShrU, 0x0003ffff, 0xffffffff, 14),
            (Instruction::I32ShrU, 0x00000001, 0xffffffff, 31),
            (Instruction::I32ShrU, 0x21212121, 0x21212121, 0),
            (Instruction::I32ShrU, 0x10909090, 0x21212121, 1),
            (Instruction::I32ShrU, 0x00424242, 0x21212121, 7),
            (Instruction::I32ShrU, 0x00008484, 0x21212121, 14),
            (Instruction::I32ShrU, 0x00000000, 0x21212121, 31),
            (Instruction::I32ShrU, 0x21212121, 0x21212121, 0xffffffe0),
            (Instruction::I32ShrU, 0x10909090, 0x21212121, 0xffffffe1),
            (Instruction::I32ShrU, 0x00424242, 0x21212121, 0xffffffe7),
            (Instruction::I32ShrU, 0x00008484, 0x21212121, 0xffffffee),
            (Instruction::I32ShrU, 0x00000000, 0x21212121, 0xffffffff),
            (Instruction::I32ShrS, 0x00000000, 0x00000000, 0),
            (Instruction::I32ShrS, 0xc0000000, 0x80000000, 1),
            (Instruction::I32ShrS, 0xff000000, 0x80000000, 7),
            (Instruction::I32ShrS, 0xfffe0000, 0x80000000, 14),
            (Instruction::I32ShrS, 0xffffffff, 0x80000001, 31),
            (Instruction::I32ShrS, 0x7fffffff, 0x7fffffff, 0),
            (Instruction::I32ShrS, 0x3fffffff, 0x7fffffff, 1),
            (Instruction::I32ShrS, 0x00ffffff, 0x7fffffff, 7),
            (Instruction::I32ShrS, 0x0001ffff, 0x7fffffff, 14),
            (Instruction::I32ShrS, 0x00000000, 0x7fffffff, 31),
            (Instruction::I32ShrS, 0x81818181, 0x81818181, 0),
            (Instruction::I32ShrS, 0xc0c0c0c0, 0x81818181, 1),
            (Instruction::I32ShrS, 0xff030303, 0x81818181, 7),
            (Instruction::I32ShrS, 0xfffe0606, 0x81818181, 14),
            (Instruction::I32ShrS, 0xffffffff, 0x81818181, 31),
        ];
        let mut shift_events: Vec<AluEvent> = Vec::new();
        for t in shifts.iter() {
            shift_events.push(AluEvent::new(0, t.0, t.1, t.2, t.3, rwasm_ins_to_code(t.0)));
        }
        let mut shard = ExecutionRecord::default();
        shard.shift_right_events = shift_events;
        let chip = ShiftRightChip::default();
        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
        let proof = prove::<BabyBearPoseidon2, _>(&config, &chip, &mut challenger, trace);

        let mut challenger = config.challenger();
        verify(&config, &chip, &mut challenger, &proof).unwrap();
    }
/*
    #[test]
    fn test_malicious_sr() {
        const NUM_TESTS: usize = 5;

        for opcode in [Instruction::I32ShrU, Instruction::I32ShrS] {
            for _ in 0..NUM_TESTS {
                let (correct_op_a, op_b, op_c) = if opcode == Instruction::I32ShrU {
                    let op_b = thread_rng().gen_range(0..u32::MAX);
                    let op_c = thread_rng().gen_range(0..u32::MAX);
                    (op_b >> (op_c & 0x1F), op_b, op_c)
                } else if opcode == Instruction::I32ShrS {
                    let op_b = thread_rng().gen_range(0..i32::MAX);
                    let op_c = thread_rng().gen_range(0..u32::MAX);
                    ((op_b >> (op_c & 0x1F)) as u32, op_b as u32, op_c)
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
                    let mut traces = prover.generate_traces(&malicious_record);
                    let shift_right_chip_name = chip_name!(ShiftRightChip, BabyBear);
                    for (name, trace) in traces.iter_mut() {
                        if *name == shift_right_chip_name {
                            let first_row = trace.row_mut(0);
                            let first_row: &mut ShiftRightCols<BabyBear> = first_row.borrow_mut();
                            first_row.a = op_a.into();
                        }
                    }
                    traces
                };

                let result =
                    run_malicious_test::<P>(program, stdin, Box::new(malicious_trace_pv_generator));
                let shift_right_chip_name = chip_name!(ShiftRightChip, BabyBear);
                assert!(
                    result.is_err()
                        && result.unwrap_err().is_constraints_failing(&shift_right_chip_name)
                );
            }
        }
    }*/
}
