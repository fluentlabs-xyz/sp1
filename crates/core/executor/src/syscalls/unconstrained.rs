use hashbrown::HashMap;

use crate::state::ForkState;

use super::{Syscall, SyscallContext};

pub(crate) struct EnterUnconstrainedSyscall;

impl Syscall for EnterUnconstrainedSyscall {
    fn execute(&self, ctx: &mut SyscallContext, _: u32, _: u32) -> Option<u32> {
        if ctx.rt.unconstrained {
            panic!("Unconstrained block is already active.");
        }
        ctx.rt.unconstrained = true;
        ctx.rt.unconstrained_state = ForkState {
            global_clk: ctx.rt.state.global_clk,
            clk: ctx.rt.state.clk,
            pc: ctx.rt.state.pc,
            memory_diff: HashMap::default(),
            record: std::mem::take(&mut ctx.rt.record),
            op_record: std::mem::take(&mut ctx.rt.memory_accesses),
            emit_events: ctx.rt.emit_events,
        };
        ctx.rt.emit_events = false;
        Some(1)
    }
}

pub(crate) struct ExitUnconstrainedSyscall;

impl Syscall for ExitUnconstrainedSyscall {
    fn execute(&self, ctx: &mut SyscallContext, _: u32, _: u32) -> Option<u32> {
        // Reset the state of the runtime.
        if ctx.rt.unconstrained {
            ctx.rt.state.global_clk = ctx.rt.unconstrained_state.global_clk;
            ctx.rt.state.clk = ctx.rt.unconstrained_state.clk;
            ctx.rt.state.pc = ctx.rt.unconstrained_state.pc;
            ctx.next_pc = ctx.rt.state.pc.wrapping_add(4);
            for (addr, value) in ctx.rt.unconstrained_state.memory_diff.drain() {
                match value {
                    Some(value) => {
                        ctx.rt.state.memory.insert(addr, value);
                    }
                    None => {
                        ctx.rt.state.memory.remove(&addr);
                    }
                }
            }
            ctx.rt.record = std::mem::take(&mut ctx.rt.unconstrained_state.record);
            ctx.rt.memory_accesses = std::mem::take(&mut ctx.rt.unconstrained_state.op_record);
            ctx.rt.emit_events = ctx.rt.unconstrained_state.emit_events;
            ctx.rt.unconstrained = false;
        }
        ctx.rt.unconstrained_state = ForkState::default();
        Some(0)
    }
}
