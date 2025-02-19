use crate::{
    events::{create_alu_lookups, AluEvent, CpuEvent, FunccallEvent},
    utils::{get_msb, get_quotient_and_remainder, is_signed_operation},
    Executor, Opcode,
};
use rwasm::{engine::{bytecode::Instruction, Instr}, rwasm::{instruction, InstructionExtra}};

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
            lookup_id: event.sub_lookups[4],
            shard: event.shard,
            clk: event.clk,
            opcode: Opcode::ADD,
            a: 0,
            b: event.c,
            c: (event.c as i32).unsigned_abs(),
            sub_lookups: create_alu_lookups(),
        });
    }
    if rem_neg == 1 {
        executor.record.add_events.push(AluEvent {
            lookup_id: event.sub_lookups[5],
            shard: event.shard,
            clk: event.clk,
            opcode: Opcode::ADD,
            a: 0,
            b: remainder,
            c: (remainder as i32).unsigned_abs(),
            sub_lookups: create_alu_lookups(),
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
        lookup_id: event.sub_lookups[0],
        shard: event.shard,
        clk: event.clk,
        opcode: Opcode::MUL,
        a: lower_word,
        c: event.c,
        b: quotient,
        sub_lookups: create_alu_lookups(),
    };
    executor.record.mul_events.push(lower_multiplication);

    let upper_multiplication = AluEvent {
        lookup_id: event.sub_lookups[1],
        shard: event.shard,
        clk: event.clk,
        opcode: {
            if is_signed_operation {
                Opcode::MULH
            } else {
                Opcode::MULHU
            }
        },
        a: upper_word,
        c: event.c,
        b: quotient,
        sub_lookups: create_alu_lookups(),
    };
    executor.record.mul_events.push(upper_multiplication);

    let lt_event = if is_signed_operation {
        AluEvent {
            lookup_id: event.sub_lookups[2],
            shard: event.shard,
            opcode: Opcode::SLTU,
            a: 1,
            b: (remainder as i32).unsigned_abs(),
            c: u32::max(1, (event.c as i32).unsigned_abs()),
            clk: event.clk,
            sub_lookups: create_alu_lookups(),
        }
    } else {
        AluEvent {
            lookup_id: event.sub_lookups[3],
            shard: event.shard,
            opcode: Opcode::SLTU,
            a: 1,
            b: remainder,
            c: u32::max(1, event.c),
            clk: event.clk,
            sub_lookups: create_alu_lookups(),
        }
    };

    if event.c != 0 {
        executor.record.lt_events.push(lt_event);
    }
}

/// Emit the dependencies for CPU events.
#[allow(clippy::too_many_lines)]
pub fn emit_cpu_dependencies(executor: &mut Executor, event: &CpuEvent) {
    if matches!(
        event.instruction,
        Instruction::I32Load(_)
            |  Instruction::I32Load16S(_)
            | Instruction::I32Load16U(_)
            | Instruction::I32Load8S(_)
            |  Instruction::I32Load8U(_)
            | Instruction::I32Store(_)
            | Instruction::I32Store16(_)
            | Instruction::I32Store8(_)
    ) {
        let offset = event.instruction.aux_value().unwrap().into();
        let memory_addr = event.arg1.wrapping_add(offset);
        // Add event to ALU check to check that addr == b + c
        let add_event = AluEvent {
            lookup_id: event.memory_add_lookup_id,
            shard: event.shard,
            clk: event.clk,
            opcode: Opcode::ADD,
            a: memory_addr,
            b: event.arg1,
            c: offset,
            sub_lookups: create_alu_lookups(),
        };
        executor.record.add_events.push(add_event);
        let addr_offset = (memory_addr % 4_u32) as u8;
        let mem_value = event.res_record.unwrap().value;

        if matches!(event.instruction, Instruction::I32Load8S(_) | Instruction::I32Load16S(_)) {
            let (unsigned_mem_val, most_sig_mem_value_byte, sign_value) =
                match event.instruction {
                    Instruction::I32Load8S(_) => {
                        let most_sig_mem_value_byte = mem_value.to_le_bytes()[addr_offset as usize];
                        let sign_value = 256;
                        (most_sig_mem_value_byte as u32, most_sig_mem_value_byte, sign_value)
                    }
                    Instruction::I32Load16S(_) => {
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
                    lookup_id: event.memory_sub_lookup_id,
                    shard: event.shard,
                    clk: event.clk,
                    opcode: Opcode::SUB,
                    a: event.res,
                    b: unsigned_mem_val,
                    c: sign_value,
                    sub_lookups: create_alu_lookups(),
                };
                executor.record.add_events.push(sub_event);
            }
        }
    }
     if matches!(
        event.instruction,
        Instruction::I32GeS |Instruction::I32GeU|
        Instruction::I32GtS |Instruction::I32GtU|
        Instruction::I32LeS|Instruction::I32LeU|
        Instruction::I32Eqz |Instruction::I32Ne|
        Instruction::I32Eq
     ){
        let use_signed_comparison = matches!(event.instruction, Instruction::I32GeS |
            Instruction::I32GtS|Instruction::I32LeS);
        let arg1_lt_arg2 = if use_signed_comparison {
            (event.arg1 as i32) < (event.arg2 as i32)
        } else {
            event.arg1 < event.arg2
        };
        let arg1_gt_arg2 = if use_signed_comparison {
            (event.arg1 as i32) > (event.arg2 as i32)
        } else {
            event.arg1 > event.arg2
        };
        let alu_op_code = if use_signed_comparison { Opcode::SLT } else { Opcode::SLTU };
        let lt_comp_event = AluEvent {
            lookup_id: event.branch_lt_lookup_id,
            shard: event.shard,
            clk: event.clk,
            opcode: alu_op_code,
            a: arg1_lt_arg2 as u32,
            b: event.arg1,
            c: event.arg2,
            sub_lookups: create_alu_lookups(),
        };
        let gt_comp_event = AluEvent {
            lookup_id: event.branch_gt_lookup_id,
            shard: event.shard,
            clk: event.clk,
            opcode: alu_op_code,
            a: arg1_gt_arg2 as u32,
            b: event.arg2,
            c: event.arg1,
            sub_lookups: create_alu_lookups(),
        };
        executor.record.lt_events.push(lt_comp_event);
        executor.record.lt_events.push(gt_comp_event);
     }
    if event.instruction.is_branch_instruction() {
        let offset =event.instruction.aux_value().unwrap().into();
        let a_eq_zero = event.arg1 == 0;
        
       
       
        let a_gt_zero = event.arg1 >0;

        let alu_op_code =  Opcode::SLTU;
        // Add the ALU events for the comparisons
        match event.instruction{
            Instruction::BrIfEqz(_)|
            Instruction::BrIfNez(_)=> {
                let gt_comp_event = AluEvent {
                    lookup_id: event.branch_gt_lookup_id,
                    shard: event.shard,
                    clk: event.clk,
                    opcode: alu_op_code,
                    a: a_gt_zero as u32,
                    b: 0,
                    c: event.arg1,
                    sub_lookups: create_alu_lookups(),
                };
                executor.record.lt_events.push(gt_comp_event);
            }
            _=>()
        }
      
        
        let branching = match event.instruction {
            Instruction::BrIfEqz(_)=>a_eq_zero,
            Instruction::BrIfNez(_)=>a_gt_zero,
            Instruction::Br(_)=>true,
            _ => unreachable!(),
        };
        if branching {
            
            let next_pc = ((event.pc as i32).wrapping_add(offset)) as u32;
            let add_event = AluEvent {
                lookup_id: event.branch_add_lookup_id,
                shard: event.shard,
                clk: event.clk,
                opcode: Opcode::ADD,
                a: next_pc,
                b: event.pc,
                c: offset as u32,
                sub_lookups: create_alu_lookups(),
            };
            executor.record.add_events.push(add_event);
        }

    }
    if matches!(event.instruction, 
        Instruction::CallInternal(_) |
                Instruction::Return(_)){
                    match event.instruction {
                        Instruction::CallInternal(func)=>{
                            let func_call_evnet = FunccallEvent{
                                shard: event.shard,
                                detph: event.depth,
                                return_pc: event.pc,
                                kind: crate::events::FunccallEventKind::FunctinonCallInternal,
                                func_index: func.to_u32(),
                                func_pc_by_index: event.next_pc,
                            };
                        executor.record.function_call_events.push(func_call_evnet);
                        },
                        Instruction::Return(_)=>{
                            // we do not need return event. it is checked by the cpu circuit.
                           ();
                        },
                        _=>()
                    }
                }

}



