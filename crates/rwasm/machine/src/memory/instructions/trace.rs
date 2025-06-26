use std::borrow::BorrowMut;

use hashbrown::HashMap;
use itertools::Itertools;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use rayon::iter::{ParallelBridge, ParallelIterator};
use rwasm::{rwasm::InstructionExtra};
use rwasm_executor::{
    events::{ByteLookupEvent, ByteRecord, MemInstrEvent}, ByteOpcode, ExecutionRecord, Instruction, Opcode, Program
};
use sp1_primitives::consts::WORD_SIZE;
use sp1_stark::air::MachineAir;

use crate::utils::{next_power_of_two, zeroed_f_vec};

use super::{
    columns::{MemoryInstructionsColumns, NUM_MEMORY_INSTRUCTIONS_COLUMNS},
    MemoryInstructionsChip,
};

impl<F: PrimeField32> MachineAir<F> for MemoryInstructionsChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        "MemoryInstrs".to_string()
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        let chunk_size = std::cmp::max((input.memory_instr_events.len()) / num_cpus::get(), 1);
        let nb_rows = input.memory_instr_events.len();
        let size_log2 = input.fixed_log2_rows::<F, _>(self);
        let padded_nb_rows = next_power_of_two(nb_rows, size_log2);
        let mut values = zeroed_f_vec(padded_nb_rows * NUM_MEMORY_INSTRUCTIONS_COLUMNS);

        let blu_events = values
            .chunks_mut(chunk_size * NUM_MEMORY_INSTRUCTIONS_COLUMNS)
            .enumerate()
            .par_bridge()
            .map(|(i, rows)| {
                let mut blu: HashMap<ByteLookupEvent, usize> = HashMap::new();
                rows.chunks_mut(NUM_MEMORY_INSTRUCTIONS_COLUMNS).enumerate().for_each(
                    |(j, row)| {
                        let idx = i * chunk_size + j;
                        let cols: &mut MemoryInstructionsColumns<F> = row.borrow_mut();

                        if idx < input.memory_instr_events.len() {
                            let event = &input.memory_instr_events[idx];
                            self.event_to_row(event, cols, &mut blu);
                        }
                    },
                );
                blu
            })
            .collect::<Vec<_>>();

        output.add_byte_lookup_events_from_maps(blu_events.iter().collect_vec());

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(values, NUM_MEMORY_INSTRUCTIONS_COLUMNS)
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.memory_instr_events.is_empty()
        }
    }

    fn local_only(&self) -> bool {
        true
    }
}

impl MemoryInstructionsChip {
    fn event_to_row<F: PrimeField32>(
        &self,
        event: &MemInstrEvent,
        cols: &mut MemoryInstructionsColumns<F>,
        blu: &mut HashMap<ByteLookupEvent, usize>,
    ) {
        cols.shard = F::from_canonical_u32(event.shard);
        assert!(cols.shard != F::zero());
        cols.clk = F::from_canonical_u32(event.clk);
        cols.pc = F::from_canonical_u32(event.pc);
        cols.op_a_value = event.res.into();
        cols.op_b_value = event.raw_addr.into();
        let offset:u32 = event.instruction.aux_value().unwrap().into();
        cols.op_c_value =offset.into();
     

        // Populate memory accesses for reading from memory.
        cols.memory_access.populate(event.mem_access, blu);

        // Populate addr_word and addr_aligned columns.
        let memory_addr = event.raw_addr.wrapping_add(offset);
        let aligned_addr = memory_addr - memory_addr % WORD_SIZE as u32;
        cols.addr_word = memory_addr.into();
        cols.addr_word_range_checker.populate(cols.addr_word, blu);
        cols.addr_aligned = F::from_canonical_u32(aligned_addr);

        // Populate the aa_least_sig_byte_decomp columns.
        assert!(aligned_addr % 4 == 0);
        // Populate memory offsets.
        let addr_ls_two_bits = (memory_addr % WORD_SIZE as u32) as u8;
        cols.addr_ls_two_bits = F::from_canonical_u8(addr_ls_two_bits);
        cols.ls_bits_is_one = F::from_bool(addr_ls_two_bits == 1);
        cols.ls_bits_is_two = F::from_bool(addr_ls_two_bits == 2);
        cols.ls_bits_is_three = F::from_bool(addr_ls_two_bits == 3);

        // Add byte lookup event to verify correct calculation of addr_ls_two_bits.
        blu.add_byte_lookup_event(ByteLookupEvent {
            opcode: ByteOpcode::AND,
            a1: addr_ls_two_bits as u16,
            a2: 0,
            b: cols.addr_word[0].as_canonical_u32() as u8,
            c: 0b11,
        });

        // If it is a load instruction, set the unsigned_mem_val column.
        let mem_value = event.mem_access.value();
        if matches!(event.instruction, Instruction::I32Load(_) | Instruction::I32Load16U(_)| 
        Instruction::I32Load16S(_)| Instruction::I32Load8U(_) | Instruction::I32Load8S(_))
        {
            match event.instruction {
                Instruction::I32Load8U(_)| Instruction::I32Load8S(_) => {
                    cols.unsigned_mem_val =
                        (mem_value.to_le_bytes()[addr_ls_two_bits as usize] as u32).into();
                }
                Instruction::I32Load16S(_) | Instruction::I32Load16U(_) => {
                    let value = match (addr_ls_two_bits >> 1) % 2 {
                        0 => mem_value & 0x0000FFFF,
                        1 => (mem_value & 0xFFFF0000) >> 16,
                        _ => unreachable!(),
                    };
                    cols.unsigned_mem_val = value.into();
                }
                Instruction::I32Load(_)=> {
                    cols.unsigned_mem_val = mem_value.into();
                }
                _ => unreachable!(),
            }

            // For the signed load instructions, we need to check if the loaded value is negative.
            if matches!(event.instruction, Instruction::I32Load8S(_) | Instruction::I32Load16S(_)) {
                let most_sig_mem_value_byte = if matches!(event.instruction, Instruction::I32Load8S(_)) {
                    cols.unsigned_mem_val.to_u32().to_le_bytes()[0]
                } else {
                    cols.unsigned_mem_val.to_u32().to_le_bytes()[1]
                };

                let most_sig_mem_value_bit = most_sig_mem_value_byte >> 7;
               

                cols.most_sig_byte = F::from_canonical_u8(most_sig_mem_value_byte);
                cols.most_sig_bit = F::from_canonical_u8(most_sig_mem_value_bit);

                blu.add_byte_lookup_event(ByteLookupEvent {
                    opcode: ByteOpcode::MSB,
                    a1: most_sig_mem_value_bit as u16,
                    a2: 0,
                    b: most_sig_mem_value_byte,
                    c: 0,
                });
            }

         
        }

        cols.is_i32load8s = F::from_bool(matches!(event.instruction, Instruction::I32Load8S(_)));
        cols.is_i32load8u = F::from_bool(matches!(event.instruction, Instruction::I32Load8U(_)));
        cols.is_i32load16s = F::from_bool(matches!(event.instruction, Instruction::I32Load16S(_)));
        cols.is_i32load16u = F::from_bool(matches!(event.instruction, Instruction::I32Load16U(_)));
        cols.is_i32load = F::from_bool(matches!(event.instruction, Instruction::I32Load(_)));
        cols.is_i32store8 = F::from_bool(matches!(event.instruction, Instruction::I32Store8(_)));
        cols.is_i32store16 = F::from_bool(matches!(event.instruction, Instruction::I32Store16(_)));
        cols.is_i32store = F::from_bool(matches!(event.instruction, Instruction::I32Store(_)));

        // Add event to byte lookup for byte range checking each byte in the memory addr
        let addr_bytes = memory_addr.to_le_bytes();
        blu.add_byte_lookup_event(ByteLookupEvent {
            opcode: ByteOpcode::U8Range,
            a1: 0,
            a2: 0,
            b: addr_bytes[1],
            c: addr_bytes[2],
        });

        cols.most_sig_bytes_zero
            .populate_from_field_element(cols.addr_word[1] + cols.addr_word[2] + cols.addr_word[3]);

        if cols.most_sig_bytes_zero.result == F::one() {
            blu.add_byte_lookup_event(ByteLookupEvent {
                opcode: ByteOpcode::LTU,
                a1: 1,
                a2: 0,
                b: 31,
                c: cols.addr_word[0].as_canonical_u32() as u8,
            });
        }
    }
}
