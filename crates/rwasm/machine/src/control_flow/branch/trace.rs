use std::borrow::BorrowMut;

use hashbrown::HashMap;
use itertools::Itertools;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use rayon::iter::{ParallelBridge, ParallelIterator};

use rwasm_executor::{
    events::{BranchEvent, ByteLookupEvent, ByteRecord},
    ExecutionRecord, Opcode, Program,
};
use sp1_stark::air::MachineAir;

use crate::utils::{next_power_of_two, zeroed_f_vec};

use super::{BranchChip, BranchColumns, NUM_BRANCH_COLS};

impl<F: PrimeField32> MachineAir<F> for BranchChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        "Branch".to_string()
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        let chunk_size = std::cmp::max((input.branch_events.len()) / num_cpus::get(), 1);
        let nb_rows = input.branch_events.len();
        let size_log2 = input.fixed_log2_rows::<F, _>(self);
        let padded_nb_rows = next_power_of_two(nb_rows, size_log2);
        let mut values = zeroed_f_vec(padded_nb_rows * NUM_BRANCH_COLS);

        let blu_events = values
            .chunks_mut(chunk_size * NUM_BRANCH_COLS)
            .enumerate()
            .par_bridge()
            .map(|(i, rows)| {
                let mut blu: HashMap<ByteLookupEvent, usize> = HashMap::new();
                rows.chunks_mut(NUM_BRANCH_COLS).enumerate().for_each(|(j, row)| {
                    let idx = i * chunk_size + j;
                    let cols: &mut BranchColumns<F> = row.borrow_mut();

                    if idx < input.branch_events.len() {
                        let event = &input.branch_events[idx];
                        self.event_to_row(event, cols, &mut blu);
                    }
                });
                blu
            })
            .collect::<Vec<_>>();

        output.add_byte_lookup_events_from_maps(blu_events.iter().collect_vec());

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(values, NUM_BRANCH_COLS)
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.branch_events.is_empty()
        }
    }

    fn local_only(&self) -> bool {
        true
    }
}

impl BranchChip {
    /// Create a row from an event.
    fn event_to_row<F: PrimeField32>(
        &self,
        event: &BranchEvent,
        cols: &mut BranchColumns<F>,
        blu: &mut HashMap<ByteLookupEvent, usize>,
    ) {
        cols.op_a_value = event.res.into();
        cols.op_b_value = event.arg1.into();
        cols.op_c_value = event.arg2.into();

        let a_eq_zero = event.arg1 == 0;
        let a_gt_zero = event.arg1 > 0;

        cols.a_eq_zero = F::from_bool(a_eq_zero);

        cols.a_gt_zero = F::from_bool(a_gt_zero);

        let branching = match event.opcode {
            Opcode::Br(_) => true,
            Opcode::BrIfEqz(_) => a_eq_zero,
            Opcode::BrIfNez(_) => !a_eq_zero,
            _ => unreachable!(),
        };

        cols.pc = event.pc.into();
        cols.next_pc = event.next_pc.into();
        cols.pc_range_checker.populate(cols.pc, blu);
        cols.next_pc_range_checker.populate(cols.next_pc, blu);

        if branching {
            cols.is_branching = F::one();
        } else {
            cols.not_branching = F::one();
        }
    }
}
