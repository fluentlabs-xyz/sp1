use rwasm_executor::RwasmAirId;
// A chip that implements the CPU.

pub struct ConstinsChip;

impl ConstinsChip {
    pub fn id(&self) -> RwasmAirId {
        RwasmAirId::Cpu
    }
}
