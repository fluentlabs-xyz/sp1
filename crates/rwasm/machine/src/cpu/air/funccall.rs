use p3_air::AirBuilder;
use p3_field::AbstractField;
use sp1_stark::{
    air::{BaseAirBuilder, SP1AirBuilder},
    Word,
};

use crate::{
    air::{SP1CoreAirBuilder, WordAirBuilder},
    cpu::{
        columns::{CpuCols, OpcodeSelectorCols},
        CpuChip,
    },
    operations::BabyBearWordRangeChecker,
};

use sp1_rwasm_executor::{Opcode, FUNFRAMEP_START};


impl CpuChip {

    pub(crate) fn is_funccall<AB: SP1AirBuilder>(
        &self,
        opcode_selectors: &OpcodeSelectorCols<AB::Var>,
    ) -> AB::Expr {
        
         opcode_selectors.is_callinternal
        + opcode_selectors.is_return
            
    }

    pub(crate) fn eval_funccall<AB: SP1CoreAirBuilder>(
        &self,
        builder: &mut AB,
        local: &CpuCols<AB::Var>,
        next:&CpuCols<AB::Var>,
        
       
    ){
        self.eval_funccall_pc_and_sp(local, next, builder);  
        // self.eval_depth(local, next, builder);
        self.eval_funccall_memory(local, builder);
        builder.send_function_call(local.instruction.aux_val.reduce::<AB>(), 
            local.next_pc,
            local.shard, 
            local.selectors.is_callinternal);
    }

    pub (crate) fn eval_funccall_pc_and_sp<AB: SP1CoreAirBuilder>(
        &self,
        local: &CpuCols<AB::Var>,
        next:&CpuCols<AB::Var>,
        builder: &mut AB,
       
    ){
        builder.when(local.selectors.is_callinternal).assert_eq(local.pc, local.op_res_val().reduce::<AB>());
        builder.when(local.selectors.is_return).
        when_ne(local.depth,AB::Expr::zero()).assert_eq(local.next_pc, local.op_arg1_val().reduce::<AB>());
        builder.when(local.selectors.is_return).
        when(local.opcode_specific_columns.funccall().depth_is_zero).assert_zero(local.next_pc);
        builder.when(local.opcode_specific_columns.funccall().depth_is_zero).assert_zero(local.depth);
        builder.when(local.selectors.is_callinternal+
        local.selectors.is_return).assert_eq(local.sp, local.next_sp);
    }
    

    pub (crate) fn eval_funccall_memory<AB: SP1CoreAirBuilder>(
        &self,
        local: &CpuCols<AB::Var>,
        builder: &mut AB,
       
    ){
        builder.eval_memory_access(local.shard, 
            local.clk+AB::Expr::from_canonical_u32(4), 
            AB::Expr::from_canonical_u32(FUNFRAMEP_START)-local.depth*AB::Expr::from_canonical_u32(4),
        &local.op_res_access, 
        local.selectors.is_callinternal);

        builder.eval_memory_access(local.shard, 
            local.clk,
            AB::Expr::from_canonical_u32(FUNFRAMEP_START)-local.next_depth*AB::Expr::from_canonical_u32(4),
        &local.op_arg1_access, 
        local.opcode_specific_columns.funccall().return_depth_is_not_zero);


        builder.eval_memory_access(local.shard, 
            local.clk,
            local.sp,
        &local.op_arg2_access, 
        local.opcode_specific_columns.funccall().dropkeep_is_one);

        builder.eval_memory_access(local.shard, 
            local.clk+AB::Expr::from_canonical_u32(4),
            local.sp+AB::Expr::from_canonical_u32(4),
        &local.op_res_access, 
        local.opcode_specific_columns.funccall().dropkeep_is_one);
    }

    pub (crate) fn eval_depth<AB: SP1CoreAirBuilder>(
        &self,
        local: &CpuCols<AB::Var>,
        next:&CpuCols<AB::Var>,
        builder: &mut AB,
       
    ){  
        builder.when(local.selectors.is_callinternal).assert_eq(local.next_depth,local.depth+AB::Expr::one());
        builder.when(local.selectors.is_return)
        .when(local.opcode_specific_columns.funccall().depth_is_zero).assert_eq(local.next_depth,local.depth-AB::Expr::one());
        builder.when(AB::Expr::one()-local.selectors.is_callinternal-local.selectors.is_return).assert_eq(local.depth, local.next_depth);
        builder.when(next.is_real).assert_eq(local.next_depth, next.depth);
    }

   
    

}
