use core::borrow::{Borrow, BorrowMut};

use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{AbstractField, PrimeField32};
use p3_matrix::Matrix;
use rwasm_executor::events::ByteRecord;
use sp1_stark::air::MachineAir;

#[cfg(test)]
mod tests {
    #![allow(clippy::print_stdout)]

    use p3_baby_bear::BabyBear;
    use p3_matrix::dense::RowMajorMatrix;
    use rwasm_executor::{events::AluEvent, rwasm_ins_to_code, ExecutionRecord, Instruction};
    use rwasm_machine::alu::DivRemChip;
    use rwasm_machine::utils::{uni_stark_prove, uni_stark_verify};
    use sp1_stark::{
        air::MachineAir, baby_bear_poseidon2::BabyBearPoseidon2, MachineProver, StarkGenericConfig,
    };

    #[test]

    fn generate_trace() {
        let mut shard = ExecutionRecord::default();
        shard.divrem_events = vec![AluEvent::new(
            0,
            Instruction::I32DivU,
            2,
            17,
            3,
            rwasm_ins_to_code(Instruction::I32DivU),
        )];
        let chip = DivRemChip::default();
        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
        println!("{:?}", trace.values)
    }

    fn neg(a: u32) -> u32 {
        u32::MAX - a + 1
    }

    #[test]
    fn prove_babybear() {
        let config = BabyBearPoseidon2::new();
        let mut challenger = config.challenger();

        let mut divrem_events: Vec<AluEvent> = Vec::new();

        let divrems: Vec<(Instruction, u32, u32, u32)> = vec![
            (Instruction::I32DivS, 3, 20, 6),
            (Instruction::I32DivS, 715827879, neg(20), 6),
            (Instruction::I32DivS, 0, 20, neg(6)),
            (Instruction::I32DivS, 0, neg(20), neg(6)),
            (Instruction::I32DivS, 1 << 31, 1 << 31, 1),
            (Instruction::I32DivS, 0, 1 << 31, neg(1)),
            (Instruction::I32DivU, u32::MAX, 1 << 31, 0),
            (Instruction::I32DivS, u32::MAX, 1, 0),
            (Instruction::I32DivS, u32::MAX, 0, 0),
            (Instruction::I32RemU, 4, 18, 7),
            (Instruction::I32RemU, 6, neg(20), 11),
            (Instruction::I32RemU, 23, 23, neg(6)),
            (Instruction::I32RemU, neg(21), neg(21), neg(11)),
            (Instruction::I32RemU, 5, 5, 0),
            (Instruction::I32RemU, neg(1), neg(1), 0),
            (Instruction::I32RemU, 0, 0, 0),
            (Instruction::I32RemS, 7, 16, 9),
            (Instruction::I32RemS, neg(4), neg(22), 6),
            (Instruction::I32RemS, 1, 25, neg(3)),
            (Instruction::I32RemS, neg(2), neg(22), neg(4)),
            (Instruction::I32RemS, 0, 873, 1),
            (Instruction::I32RemS, 0, 873, neg(1)),
            (Instruction::I32RemS, 5, 5, 0),
            (Instruction::I32RemS, neg(5), neg(5), 0),
            (Instruction::I32RemS, 0, 0, 0),
            (Instruction::I32RemS, 0, 0x80000001, neg(1)),
            (Instruction::I32DivS, 3, 18, 6),
            (Instruction::I32DivS, neg(6), neg(24), 4),
            (Instruction::I32DivS, neg(2), 16, neg(8)),
            (Instruction::I32DivS, neg(1), 0, 0),
            (Instruction::I32DivS, 1 << 31, 1 << 31, neg(1)),
            (Instruction::I32RemS, 0, 1 << 31, neg(1)),
        ];
        for t in divrems.iter() {
            divrem_events.push(AluEvent::new(0, t.0, t.1, t.2, t.3, rwasm_ins_to_code(t.0)));
        }

        // Append more events until we have 1000 tests.
        for _ in 0..(1000 - divrems.len()) {
            divrem_events.push(AluEvent::new(
                0,
                Instruction::I32DivS,
                1,
                1,
                1,
                rwasm_ins_to_code(Instruction::I32DivS),
            ));
        }

        let mut shard = ExecutionRecord::default();
        shard.divrem_events = divrem_events;
        let chip = DivRemChip::default();
        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
        let proof = uni_stark_prove::<BabyBearPoseidon2, _>(&config, &chip, &mut challenger, trace);

        let mut challenger = config.challenger();
        uni_stark_verify(&config, &chip, &mut challenger, &proof).unwrap();
    }

    // #[test]
    // fn test_malicious_divrem() {
    //     const NUM_TESTS: usize = 5;

    //     for opcode in [
    //         Instruction::I32DivS,
    //         Instruction::I32DivSU,
    //         Instruction::I32RemS,
    //         Instruction::I32RemU,
    //     ] {
    //         for _ in 0..NUM_TESTS {
    //             let (correct_op_a, op_b, op_c) = if opcode == Instruction::I32DivS {
    //                 let op_b = thread_rng().gen_range(0..i32::MAX);
    //                 let op_c = thread_rng().gen_range(0..i32::MAX);
    //                 ((op_b / op_c) as u32, op_b as u32, op_c as u32)
    //             } else if opcode == Instruction::I32DivSU {
    //                 let op_b = thread_rng().gen_range(0..u32::MAX);
    //                 let op_c = thread_rng().gen_range(0..u32::MAX);
    //                 (op_b / op_c, op_b as u32, op_c as u32)
    //             } else if opcode == Instruction::I32RemS {
    //                 let op_b = thread_rng().gen_range(0..i32::MAX);
    //                 let op_c = thread_rng().gen_range(0..i32::MAX);
    //                 ((op_b % op_c) as u32, op_b as u32, op_c as u32)
    //             } else if opcode == Instruction::I32RemU {
    //                 let op_b = thread_rng().gen_range(0..u32::MAX);
    //                 let op_c = thread_rng().gen_range(0..u32::MAX);
    //                 (op_b % op_c, op_b as u32, op_c as u32)
    //             } else {
    //                 unreachable!()
    //             };

    //             let op_a = thread_rng().gen_range(0..u32::MAX);
    //             assert!(op_a != correct_op_a);

    //             let instructions = vec![
    //                 Instruction::new(opcode, 5, op_b, op_c, true, true),
    //                 Instruction::new(Opcode::ADD, 10, 0, 0, false, false),
    //             ];

    //             let program = Program::new(instructions, 0, 0);
    //             let stdin = SP1Stdin::new();

    //             type P = CpuProver<BabyBearPoseidon2, RiscvAir<BabyBear>>;

    //             let malicious_trace_pv_generator = move |prover: &P,
    //                                                      record: &mut ExecutionRecord|
    //                   -> Vec<(
    //                 String,
    //                 RowMajorMatrix<Val<BabyBearPoseidon2>>,
    //             )> {
    //                 let mut malicious_record = record.clone();
    //                 malicious_record.cpu_events[0].a = op_a;
    //                 if let Some(MemoryRecordEnum::Write(mut write_record)) =
    //                     malicious_record.cpu_events[0].a_record
    //                 {
    //                     write_record.value = op_a;
    //                 }
    //                 malicious_record.divrem_events[0].a = op_a;
    //                 prover.generate_traces(&malicious_record)
    //             };

    //             let result =
    //                 run_malicious_test::<P>(program, stdin, Box::new(malicious_trace_pv_generator));
    //             let divrem_chip_name = chip_name!(DivRemChip, BabyBear);
    //             assert!(
    //                 result.is_err()
    //                     && result.unwrap_err().is_constraints_failing(&divrem_chip_name)
    //             );
    //         }
    //     }
    // }
}
