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
use sp1_rwasm_executor::{ Opcode};

impl CpuChip {

    pub(crate) fn is_local_set<AB: SP1AirBuilder>(
        &self,
        opcode_selectors: &OpcodeSelectorCols<AB::Var>,
    ) -> AB::Expr {
        
         opcode_selectors.is_localset 
        + opcode_selectors.is_localtee
            
    }

    pub(crate) fn eval_local<AB: SP1CoreAirBuilder>(
        &self,
        builder: &mut AB,
        local: &CpuCols<AB::Var>,
        is_local_set:AB::Expr
       
    ){
        self.eval_local_memory(builder, local);
        self.eval_local_sp(builder, local);
    }

    pub(crate) fn eval_local_sp<AB: SP1CoreAirBuilder>(
        &self,
        builder: &mut AB,
        local: &CpuCols<AB::Var>,
       
    ){
        builder.when(local.selectors.is_localget).assert_eq(local.next_sp, local.sp-AB::Expr::from_canonical_u8(4));
        builder.when(local.selectors.is_localset).assert_eq(local.next_sp, local.sp+AB::Expr::from_canonical_u8(4));
        builder.when(local.selectors.is_localtee).assert_eq(local.next_sp, local.sp);

    }

    pub(crate) fn eval_local_memory<AB: SP1CoreAirBuilder>(
        &self,
        builder: &mut AB,
        local: &CpuCols<AB::Var>,
       
    ){
        builder.eval_memory_access(
            local.shard,
            local.clk ,
            local.sp+local.instruction.aux_val.reduce::<AB>(),
            &local.op_arg1_access,
            local.selectors.is_localget,
        );


        builder.eval_memory_access(
            local.shard,
            local.clk +AB::Expr::from_canonical_u8(4),
            local.next_sp +local.instruction.aux_val.reduce::<AB>(),
            &local.op_res_access,
            local.selectors.is_localset
        );

        builder.eval_memory_access(
            local.shard,
            local.clk +AB::Expr::from_canonical_u8(4),
            local.sp +local.instruction.aux_val.reduce::<AB>(),
            &local.op_res_access,
            local.selectors.is_localtee
        );
            
    }

    

}
