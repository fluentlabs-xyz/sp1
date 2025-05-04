

#[cfg(test)]
pub mod test {
    
    #![allow(clippy::print_stdout)]

    use p3_baby_bear::BabyBear;
    use p3_matrix::dense::RowMajorMatrix;
    use rand::{thread_rng, Rng};
    use rwasm_executor::{
        events::{AluEvent, MemoryRecordEnum},
        ExecutionRecord, Instruction, Opcode, DEFAULT_PC_INC,
    };
    use sp1_stark::{
        air::MachineAir, baby_bear_poseidon2::BabyBearPoseidon2, chip_name, CpuProver,
        MachineProver, StarkGenericConfig, Val,
    };
    use std::sync::LazyLock;

    use super::*;
    use crate::{
        io::SP1Stdin,
        rwasm::RwasmAir as RwasmAir,
        utils::{run_malicious_test, uni_stark_prove as prove, uni_stark_verify as verify},
    };

    /// Lazily initialized record for use across multiple tests.
    /// Consists of random `ADD` and `SUB` instructions.
    static SHARD: LazyLock<ExecutionRecord> = LazyLock::new(|| {
        let add_events = (0..1)
            .flat_map(|i| {
                [{
                    let operand_1 = 1u32;
                    let operand_2 = 2u32;
                    let result = operand_1.wrapping_add(operand_2);
                    AluEvent::new(i % 2, Opcode::ADD, result, operand_1, operand_2)
                }]
            })
            .collect::<Vec<_>>();
        let _sub_events = (0..255)
            .flat_map(|i| {
                [{
                    let operand_1 = thread_rng().gen_range(0..u32::MAX);
                    let operand_2 = thread_rng().gen_range(0..u32::MAX);
                    let result = operand_1.wrapping_add(operand_2);
                    AluEvent::new(i % 2, Instruction::I32Sub, result, operand_1, operand_2)
                }]
            })
            .collect::<Vec<_>>();
        ExecutionRecord { add_events, ..Default::default() }
    });

    #[test]
    fn generate_trace() {
        let mut shard = ExecutionRecord::default();
        shard.add_events = vec![AluEvent::new(0, Opcode::ADD, 14, 8, 6)];
        let chip = AddSubChip::default();
        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
        println!("{:?}", trace.values)
    }
}
