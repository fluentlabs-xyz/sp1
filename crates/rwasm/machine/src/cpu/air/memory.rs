use p3_air::AirBuilder;
use p3_field::AbstractField;
use sp1_stark::{air::SP1AirBuilder, Word};

use crate::{
    air::{SP1CoreAirBuilder, WordAirBuilder},
    cpu::{
        columns::{CpuCols, MemoryColumns, OpcodeSelectorCols},
        CpuChip,
    },
    memory::MemoryCols,
    operations::BabyBearWordRangeChecker,
};
use sp1_rwasm_executor::{events::MemoryAccessPosition, Opcode};

impl CpuChip {
    /// Computes whether the opcode is a memory instruction.
    pub(crate) fn is_memory_instruction<AB: SP1AirBuilder>(
        &self,
        opcode_selectors: &OpcodeSelectorCols<AB::Var>,
    ) -> AB::Expr {
        todo!()
    }

    /// Computes whether the opcode is a load instruction.
    pub(crate) fn is_load_instruction<AB: SP1AirBuilder>(
        &self,
        opcode_selectors: &OpcodeSelectorCols<AB::Var>,
    ) -> AB::Expr {
        todo!()
    }

    /// Computes whether the opcode is a store instruction.
    pub(crate) fn is_store_instruction<AB: SP1AirBuilder>(
        &self,
        opcode_selectors: &OpcodeSelectorCols<AB::Var>,
    ) -> AB::Expr {
        todo!()
    }

     /// Computes whether the opcode is a store instruction.
     pub(crate) fn is_branch_instruction<AB: SP1AirBuilder>(
        &self,
        opcode_selectors: &OpcodeSelectorCols<AB::Var>,
    ) -> AB::Expr {
        todo!()
    }

   

}
