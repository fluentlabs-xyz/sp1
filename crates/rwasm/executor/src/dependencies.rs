use rwasm::Opcode;

use crate::{
    events::{AluEvent, BranchEvent, MemInstrEvent, MemoryRecord},
    utils::{get_msb, get_quotient_and_remainder, is_signed_operation},
    Executor, I32MULHU_CODE, I32MULH_CODE, UNUSED_PC,
};

/// Emits the dependencies for division and remainder operations.
#[allow(clippy::too_many_lines)]
pub fn emit_divrem_dependencies(executor: &mut Executor, event: AluEvent) {
    let (quotient, remainder) = get_quotient_and_remainder(event.b, event.c, event.opcode);
    let c_msb = get_msb(event.c);
    let rem_msb = get_msb(remainder);
    let mut c_neg = 0;
    let mut rem_neg = 0;
    let is_signed_operation = is_signed_operation(event.opcode);
    if is_signed_operation {
        c_neg = c_msb; // same as abs_c_alu_event
        rem_neg = rem_msb; // same as abs_rem_alu_event
    }

    if c_neg == 1 {
        executor.record.add_events.push(AluEvent {
            pc: UNUSED_PC,
            opcode: Opcode::I32Add,
            a: 0,
            b: event.c,
            c: (event.c as i32).unsigned_abs(),
            code: Opcode::I32Add.code(),
        });
    }
    if rem_neg == 1 {
        executor.record.add_events.push(AluEvent {
            pc: UNUSED_PC,
            opcode: Opcode::I32Add,
            a: 0,
            b: remainder,
            c: (remainder as i32).unsigned_abs(),
            code: Opcode::I32Add.code(),
        });
    }

    let c_times_quotient = {
        if is_signed_operation {
            (((quotient as i32) as i64) * ((event.c as i32) as i64)).to_le_bytes()
        } else {
            ((quotient as u64) * (event.c as u64)).to_le_bytes()
        }
    };
    let lower_word = u32::from_le_bytes(c_times_quotient[0..4].try_into().unwrap());
    let upper_word = u32::from_le_bytes(c_times_quotient[4..8].try_into().unwrap());

    let lower_multiplication = AluEvent {
        pc: UNUSED_PC,
        opcode: Opcode::I32Mul,
        a: lower_word,
        c: event.c,
        b: quotient,
        code: Opcode::I32Mul.code(),
    };
    executor.record.mul_events.push(lower_multiplication);

    let upper_multiplication = AluEvent {
        pc: UNUSED_PC,
        opcode: Opcode::I32Mul,
        a: upper_word,
        c: event.c,
        b: quotient,
        code: {
            if is_signed_operation {
                I32MULH_CODE
            } else {
                I32MULHU_CODE
            }
        },
    };
    executor.record.mul_events.push(upper_multiplication);

    let lt_event = if is_signed_operation {
        AluEvent {
            pc: UNUSED_PC,
            opcode: Opcode::I32LtU,
            a: 1,
            b: (remainder as i32).unsigned_abs(),
            c: u32::max(1, (event.c as i32).unsigned_abs()),
            code: Opcode::I32LtU.code(),
        }
    } else {
        AluEvent {
            pc: UNUSED_PC,
            opcode: Opcode::I32LtU,
            a: 1,
            b: remainder,
            c: u32::max(1, event.c),
            code: Opcode::I32LtU.code(),
        }
    };

    if event.c != 0 {
        executor.record.lt_events.push(lt_event);
    }
}

/// Emit the dependencies for memory opcodes.
pub fn emit_memory_dependencies(executor: &mut Executor, event: MemInstrEvent, _: MemoryRecord) {
    if matches!(
        event.opcode,
        Opcode::I32Load(_)
            | Opcode::I32Load16S(_)
            | Opcode::I32Load16U(_)
            | Opcode::I32Load8S(_)
            | Opcode::I32Load8U(_)
            | Opcode::I32Store(_)
            | Opcode::I32Store16(_)
            | Opcode::I32Store8(_)
    ) {
        let offset = event.opcode.aux_value();
        let memory_addr = event.arg1.wrapping_add(offset);
        // Add event to ALU check to check that addr == b + c
        let add_event = AluEvent {
            pc: UNUSED_PC,
            opcode: Opcode::I32Add,
            a: memory_addr,
            b: event.arg1,
            c: offset,
            code: Opcode::I32Add.code(),
        };
        executor.record.add_events.push(add_event);
        let addr_offset = (memory_addr % 4_u32) as u8;
        let mem_value = event.mem_access.value();

        if matches!(event.opcode, Opcode::I32Load8S(_) | Opcode::I32Load16S(_)) {
            let (unsigned_mem_val, most_sig_mem_value_byte, sign_value) = match event.opcode {
                Opcode::I32Load8S(_) => {
                    let most_sig_mem_value_byte = mem_value.to_le_bytes()[addr_offset as usize];
                    let sign_value = 256;
                    (most_sig_mem_value_byte as u32, most_sig_mem_value_byte, sign_value)
                }
                Opcode::I32Load16S(_) => {
                    let sign_value = 65536;
                    let unsigned_mem_val = match (addr_offset >> 1) % 2 {
                        0 => mem_value & 0x0000FFFF,
                        1 => (mem_value & 0xFFFF0000) >> 16,
                        _ => unreachable!(),
                    };
                    let most_sig_mem_value_byte = unsigned_mem_val.to_le_bytes()[1];
                    (unsigned_mem_val, most_sig_mem_value_byte, sign_value)
                }
                _ => unreachable!(),
            };

            if most_sig_mem_value_byte >> 7 & 0x01 == 1 {
                let sub_event = AluEvent {
                    pc: UNUSED_PC,
                    opcode: Opcode::I32Sub,
                    a: event.res,
                    b: unsigned_mem_val,
                    c: sign_value,
                    code: Opcode::I32Sub.code(),
                };
                executor.record.add_events.push(sub_event);
            }
        }
    }
}

/// Emit the dependencies for branch opcodes.
pub fn emit_branch_dependencies(executor: &mut Executor, event: BranchEvent) {
    if event.opcode.is_branch_instruction() {
        let offset = event.opcode.aux_value();
        let a_eq_zero = event.arg1 == 0;

        let a_gt_zero = event.arg1 > 0;

        let cmp_ins = Opcode::I32LtU;
        // Add the ALU events for the comparisons
        match event.opcode {
            Opcode::BrIfEqz(_) | Opcode::BrIfNez(_) => {
                let gt_comp_event = AluEvent {
                    pc: UNUSED_PC,
                    opcode: cmp_ins,
                    a: a_gt_zero as u32,
                    b: 0,
                    c: event.arg1,
                    code: cmp_ins.code(),
                };
                executor.record.lt_events.push(gt_comp_event);
            }
            _ => (),
        }

        let branching = match event.opcode {
            Opcode::BrIfEqz(_) => a_eq_zero,
            Opcode::BrIfNez(_) => a_gt_zero,
            Opcode::Br(_) => true,
            _ => unreachable!(),
        };
        if branching {
            let next_pc = ((event.pc).wrapping_add(offset)) as u32;
            let add_event = AluEvent {
                pc: UNUSED_PC,
                opcode: Opcode::I32Add,
                a: next_pc,
                b: event.pc,
                c: offset as u32,
                code: Opcode::I32Add.code(),
            };
            executor.record.add_events.push(add_event);
        }
    }
}
