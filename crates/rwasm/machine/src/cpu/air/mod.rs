pub mod branch;
pub mod ecall;
pub mod memory;
pub mod local;
pub mod funccall;
use core::borrow::Borrow;
use p3_air::{Air, AirBuilder, AirBuilderWithPublicValues, BaseAir};
use p3_field::AbstractField;
use p3_matrix::Matrix;
use sp1_rwasm_executor::ByteOpcode;
use sp1_stark::{
    air::{BaseAirBuilder, PublicValues, SP1AirBuilder, SP1_PROOF_NUM_PV_ELTS},
    Word,
};
use crate::air::WordAirBuilder;

use crate::{
    air::{MemoryAirBuilder, SP1CoreAirBuilder}, cpu::{
        columns::{CpuCols, OpcodeSelectorCols, NUM_CPU_COLS},
        CpuChip,
    }, memory::MemoryCols, operations::BabyBearWordRangeChecker
};
use sp1_rwasm_executor::Opcode;

use super::columns::OPCODE_SELECTORS_COL_MAP;

impl<AB> Air<AB> for CpuChip
where
    AB: SP1CoreAirBuilder + AirBuilderWithPublicValues,
    AB::Var: Sized,
{
    #[inline(never)]
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let (local, next) = (main.row_slice(0), main.row_slice(1));
        let local: &CpuCols<AB::Var> = (*local).borrow();
        let next: &CpuCols<AB::Var> = (*next).borrow();
        let public_values_slice: [AB::Expr; SP1_PROOF_NUM_PV_ELTS] =
            core::array::from_fn(|i| builder.public_values()[i].into());
        let public_values: &PublicValues<Word<AB::Expr>, AB::Expr> =
            public_values_slice.as_slice().borrow();

        // Program constraints.
        builder.send_program(
            local.pc,
            local.instruction,
            local.selectors,
            local.shard,
            local.is_real,
        );

        builder.when(local.is_real).assert_bool(local.instruction.is_unary);
        builder.when(local.is_real).assert_bool(local.instruction.is_binary);
        builder.when(local.is_real).assert_bool(local.instruction.is_memory);
        builder.when(local.is_real).assert_bool(local.instruction.is_branching);
        builder.when(local.is_real).assert_bool(local.instruction.is_local);
        builder.when(local.is_real).assert_bool(local.instruction.is_call);
        builder.when(local.is_real).assert_one(local.instruction.is_unary+local.instruction.is_binary+
            local.instruction.is_memory+local.instruction.is_branching+
            local.instruction.is_local+
            local.instruction.is_call
        +local.selectors.is_i32const+local.selectors.is_skipped);
        // Compute some flags for which type of instruction we are dealing with.
        let is_memory_instruction: AB::Expr = self.is_memory_instruction::<AB>(&local.selectors);
        let is_memory_load: AB::Expr = self.is_load_instruction::<AB>(&local.selectors);
        let is_memory_store: AB::Expr = self.is_store_instruction::<AB>(&local.selectors);
        // let is_branch_instruction: AB::Expr = self.is_branch_instruction::<AB>(&local.selectors);



        // Memory instructions.
        self.eval_memory_address_and_access::<AB>(builder, local, 
            is_memory_instruction.clone(),
            is_memory_load.clone(),
            is_memory_store.clone()
        );
        self.eval_memory_load::<AB>(builder, local);
        self.eval_memory_store::<AB>(builder, local);
        
        let is_branch_instruction: AB::Expr = self.is_branch_instruction::<AB>(&local.selectors);
        let is_funccall_instruction: AB::Expr = self.is_funccall::<AB>(&local.selectors);
        self.eval_alu_ops(builder, local);

        // Branch instructions.
        self.eval_branch_ops::<AB>(builder, is_branch_instruction.clone(), local, next);
      
        let is_local_set : AB::Expr = self.is_local_set::<AB>(&local.selectors);
        //Local instructions.
        self.eval_local::<AB>(builder,local,is_local_set);

        self.eval_funccall::<AB>(builder,local,next);
        // // AUIPC instruction.
        // self.eval_auipc(builder, local);

        // // ECALL instruction.
        // self.eval_ecall(builder, local);

        // COMMIT/COMMIT_DEFERRED_PROOFS ecall instruction.
        // self.eval_commit(
        //     builder,
        //     local,
        //     public_values.committed_value_digest.clone(),
        //     public_values.deferred_proofs_digest.clone(),
        // );

        // HALT ecall and UNIMPL instruction.
        // self.eval_halt_unimpl(builder, local, next, public_values);

        // Check that the shard and clk is updated correctly.
        self.eval_shard_clk(builder, local, next);

        // Check that the pc is updated correctly.
        self.eval_pc(builder, local, next, is_branch_instruction.clone(),is_funccall_instruction.clone());

        // // Check that the sp is updated correctly.
        // self.eval_sp(builder, local, next);

        // Check public values constraints.
        self.eval_public_values(builder, local, next, public_values);

        //check op memory access
        
        self.eval_op_memory(builder, local);
        // Check that the is_real flag is correct.
        self.eval_is_real(builder, local, next);
    }


    
}

impl CpuChip {
   /// Whether the instruction is an ALU instruction.
   pub(crate) fn is_ordinary_alu_instruction<AB: SP1AirBuilder>(
    &self,
    opcode_selectors: &OpcodeSelectorCols<AB::Var>,
) -> AB::Expr {
    opcode_selectors.is_ordinary_alu.into()
}

 /// Whether the instruction is an ALU instruction.
 pub(crate) fn is_comparision_alu_instruction<AB: SP1AirBuilder>(
    &self,
    opcode_selectors: &OpcodeSelectorCols<AB::Var>,
) -> AB::Expr {
    opcode_selectors.is_comparison_alu.into()
}

    // /// Constraints related to jump operations.
    // pub(crate) fn eval_jump_ops<AB: SP1AirBuilder>(
    //     &self,
    //     builder: &mut AB,
    //     local: &CpuCols<AB::Var>,
    //     next: &CpuCols<AB::Var>,
    // ) {
    //     // Get the jump specific columns
    //     let jump_columns = local.opcode_specific_columns.jump();

    //     let is_jump_instruction = local.selectors.is_jal + local.selectors.is_jalr;

    //     // Verify that the local.pc + 4 is saved in op_a for both jump instructions.
    //     // When op_a is set to register X0, the RISC-V spec states that the jump instruction will
    //     // not have a return destination address (it is effectively a GOTO command).  In this case,
    //     // we shouldn't verify the return address.
    //     builder
    //         .when(is_jump_instruction.clone())
    //         .when_not(local.instruction.op_a_0)
    //         .assert_eq(local.op_a_val().reduce::<AB>(), local.pc + AB::F::from_canonical_u8(4));

    //     // Verify that the word form of local.pc is correct for JAL instructions.
    //     builder.when(local.selectors.is_jal).assert_eq(jump_columns.pc.reduce::<AB>(), local.pc);

    //     // Verify that the word form of next.pc is correct for both jump instructions.
    //     builder
    //         .when_transition()
    //         .when(next.is_real)
    //         .when(is_jump_instruction.clone())
    //         .assert_eq(jump_columns.next_pc.reduce::<AB>(), next.pc);

    //     // When the last row is real and it's a jump instruction, assert that local.next_pc <==>
    //     // jump_column.next_pc
    //     builder
    //         .when(local.is_real)
    //         .when(is_jump_instruction.clone())
    //         .assert_eq(jump_columns.next_pc.reduce::<AB>(), local.next_pc);

    //     // Range check op_a, pc, and next_pc.
    //     BabyBearWordRangeChecker::<AB::F>::range_check(
    //         builder,
    //         local.op_a_val(),
    //         jump_columns.op_a_range_checker,
    //         is_jump_instruction.clone(),
    //     );
    //     BabyBearWordRangeChecker::<AB::F>::range_check(
    //         builder,
    //         jump_columns.pc,
    //         jump_columns.pc_range_checker,
    //         local.selectors.is_jal.into(),
    //     );
    //     BabyBearWordRangeChecker::<AB::F>::range_check(
    //         builder,
    //         jump_columns.next_pc,
    //         jump_columns.next_pc_range_checker,
    //         is_jump_instruction.clone(),
    //     );

    //     // Verify that the new pc is calculated correctly for JAL instructions.
    //     builder.send_alu(
    //         AB::Expr::from_canonical_u32(Opcode::ADD as u32),
    //         jump_columns.next_pc,
    //         jump_columns.pc,
    //         local.op_b_val(),
    //         local.shard,
    //         jump_columns.jal_nonce,
    //         local.selectors.is_jal,
    //     );

    //     // Verify that the new pc is calculated correctly for JALR instructions.
    //     builder.send_alu(
    //         AB::Expr::from_canonical_u32(Opcode::ADD as u32),
    //         jump_columns.next_pc,
    //         local.op_b_val(),
    //         local.op_c_val(),
    //         local.shard,
    //         jump_columns.jalr_nonce,
    //         local.selectors.is_jalr,
    //     );
    // }

    // /// Constraints related to the AUIPC opcode.
    // pub(crate) fn eval_auipc<AB: SP1AirBuilder>(&self, builder: &mut AB, local: &CpuCols<AB::Var>) {
    //     // Get the auipc specific columns.
    //     let auipc_columns = local.opcode_specific_columns.auipc();

    //     // Verify that the word form of local.pc is correct.
    //     builder.when(local.selectors.is_auipc).assert_eq(auipc_columns.pc.reduce::<AB>(), local.pc);

    //     // Range check the pc.
    //     BabyBearWordRangeChecker::<AB::F>::range_check(
    //         builder,
    //         auipc_columns.pc,
    //         auipc_columns.pc_range_checker,
    //         local.selectors.is_auipc.into(),
    //     );

    //     // Verify that op_a == pc + op_b.
    //     builder.send_alu(
    //         AB::Expr::from_canonical_u32(Opcode::ADD as u32),
    //         local.op_a_val(),
    //         auipc_columns.pc,
    //         local.op_b_val(),
    //         local.shard,
    //         auipc_columns.auipc_nonce,
    //         local.selectors.is_auipc,
    //     );
    // }

    /// Constraints related to the shard and clk.
    ///
    /// This method ensures that all of the shard values are the same and that the clk starts at 0
    /// and is transitioned appropriately.  It will also check that shard values are within 16 bits
    /// and clk values are within 24 bits.  Those range checks are needed for the memory access
    /// timestamp check, which assumes those values are within 2^24.  See
    /// [`MemoryAirBuilder::verify_mem_access_ts`].
    pub(crate) fn eval_shard_clk<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        local: &CpuCols<AB::Var>,
        next: &CpuCols<AB::Var>,
    ) {
        // Verify that all shard values are the same.
        builder.when_transition().when(next.is_real).assert_eq(local.shard, next.shard);

        // Verify that the shard value is within 16 bits.
        builder.send_byte(
            AB::Expr::from_canonical_u8(ByteOpcode::U16Range as u8),
            local.shard,
            AB::Expr::zero(),
            AB::Expr::zero(),
            local.is_real,
        );

        // Verify that the first row has a clk value of 0.
        builder.when_first_row().assert_zero(local.clk);

        // Verify that the clk increments are correct.  Most clk increment should be 4, but for some
        // precompiles, there are additional cycles.
        // let num_extra_cycles = self.get_num_extra_ecall_cycles::<AB>(local);

        // We already assert that `local.clk < 2^24`. `num_extra_cycles` is an entry of a word and
    //     // therefore less than `2^8`, this means that the sum cannot overflow in a 31 bit field.
        let expected_next_clk = local.clk + AB::Expr::from_canonical_u32(8);
        let expected_next_clk_branching = local.clk + AB::Expr::from_canonical_u32(4);
        // +  num_extra_cycles.clone()

        builder.when_transition().when(next.is_real*(AB::Expr::one()-local.selectors.is_branching))
        .assert_eq(expected_next_clk.clone(), next.clk);
    builder.when_transition().when(next.is_real*local.selectors.is_branching)
        .assert_eq(expected_next_clk_branching.clone(), next.clk);

        // Range check that the clk is within 24 bits using it's limb values.
        builder.eval_range_check_24bits(
            local.clk,
            local.clk_16bit_limb,
            local.clk_8bit_limb,
            local.is_real,
        );
    }

    /// Constraints related to the pc for non jump, branch, and halt instructions.
    ///
    /// The function will verify that the pc increments by 4 for all instructions except branch,
    /// jump and halt instructions. Also, it ensures that the pc is carried down to the last row
    /// for non-real rows.
    pub(crate) fn eval_pc<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        local: &CpuCols<AB::Var>,
        next: &CpuCols<AB::Var>,
        is_branch_instruction: AB::Expr,
        is_funccall_instruction:AB::Expr,
    ) {
        // When is_sequential_instr is true, assert that instruction is not branch, jump, or halt.
        // Note that the condition `when(local_is_real)` is implied from the previous constraint.
        // let is_halt = self.get_is_halt_syscall::<AB>(builder, local);
        builder.when(local.is_real).assert_eq(
            local.is_sequential_instr,
            AB::Expr::one()
                - (
                    is_branch_instruction
                    +is_funccall_instruction
                    // + local.selectors.is_jal
                    // + local.selectors.is_jalr
                    // + is_halt),
                ),
        );

        // Verify that the pc increments by 4 for all instructions except branch, jump and halt
        // instructions. The other case is handled by eval_jump, eval_branch and eval_ecall
        // (for halt).
        builder
            .when_transition()
            .when(next.is_real)
            .when(local.is_sequential_instr)
            .assert_eq(local.pc + AB::Expr::from_canonical_u8(4), next.pc);

        // When the last row is real and it's a sequential instruction, assert that local.next_pc
        // <==> local.pc + 4
        builder
            .when(local.is_real)
            .when(local.is_sequential_instr)
            .assert_eq(local.pc + AB::Expr::from_canonical_u8(4), local.next_pc);
    }

     /// Constraints related to the pc for non jump, branch, and halt instructions.
    ///
    /// The function will verify that the pc increments by 4 for all instructions except branch,
    /// jump and halt instructions. Also, it ensures that the pc is carried down to the last row
    /// for non-real rows.
    pub(crate) fn eval_sp<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        local: &CpuCols<AB::Var>,
        next: &CpuCols<AB::Var>,
    ) {
        

        //verfiy that when next is real then next start sp equals local's sp
        builder
            .when_transition()
            .when(next.is_real)
            .assert_eq(next.sp , local.next_sp);

        //verify that sp decreses by 4 if op is binary.
        builder
            .when(local.is_real)
            .when(local.instruction.is_binary)
            .assert_eq(local.next_sp + AB::Expr::from_canonical_u8(4), local.sp);

       

         //verify that sp remains the same if op is unary.
         builder
         .when(local.is_real)
         .when(local.instruction.is_unary)
         .assert_eq(local.next_sp,local.sp);

         //verify that sp increase by 4 if op is i32const
         builder
         .when(local.is_real)
         .when(local.selectors.is_i32const)
         .assert_eq(local.next_sp + AB::Expr::from_canonical_u8(4), local.sp);

    }


    /// Constraints related to the public values.
    pub(crate) fn eval_public_values<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        local: &CpuCols<AB::Var>,
        next: &CpuCols<AB::Var>,
        public_values: &PublicValues<Word<AB::Expr>, AB::Expr>,
    ) {
        // Verify the public value's shard.
        builder.when(local.is_real).assert_eq(public_values.execution_shard.clone(), local.shard);

        // Verify the public value's start pc.
        builder.when_first_row().assert_eq(public_values.start_pc.clone(), local.pc);

        // Verify the public value's next pc.  We need to handle two cases:
        // 1. The last real row is a transition row.
        // 2. The last real row is the last row.

        // If the last real row is a transition row, verify the public value's next pc.
        builder
            .when_transition()
            .when(local.is_real - next.is_real)
            .assert_eq(public_values.next_pc.clone(), local.next_pc);

        // If the last real row is the last row, verify the public value's next pc.
        builder
            .when_last_row()
            .when(local.is_real)
            .assert_eq(public_values.next_pc.clone(), local.next_pc);
    }

    /// Constraints related to the is_real column.
    ///
    /// This method checks that the is_real column is a boolean.  It also checks that the first row
    /// is 1 and once its 0, it never changes value.
    pub(crate) fn eval_is_real<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        local: &CpuCols<AB::Var>,
        next: &CpuCols<AB::Var>,
    ) {
        // Check the is_real flag.  It should be 1 for the first row.  Once its 0, it should never
        // change value.
        builder.assert_bool(local.is_real);
        builder.when_first_row().assert_one(local.is_real);
        builder.when_transition().when_not(local.is_real).assert_zero(next.is_real);
    }

    fn eval_op_memory<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        local: &CpuCols<AB::Var>,
    ){
        let shard = local.shard;
        let clk = local.clk;
        //make sure the memory access are correct
        //always need to check arg1
        //only check arg2 if instruction is binary
        builder.eval_memory_access(shard, clk, local.sp, &local.op_arg1_access, local.is_real-local.instruction.is_nullary-local.selectors.is_localget-local.instruction.is_call-local.selectors.is_skipped-local.instruction.is_binary);
        builder.eval_memory_access(shard, clk, local.sp, &local.op_arg2_access, local.instruction.is_binary);
        builder.eval_memory_access(shard, clk, local.sp + AB::Expr::from_canonical_u8(4), 
        &local.op_arg1_access, local.instruction.is_binary);
        
        builder.eval_memory_access(shard, clk + AB::Expr::from_canonical_u8(4),
         local.sp + AB::Expr::from_canonical_u8(4), &local.op_res_access, local.instruction.is_binary);
         builder.eval_memory_access(shard, clk + AB::Expr::from_canonical_u8(4),
         local.sp, &local.op_res_access, local.instruction.is_unary);

         builder.eval_memory_access(shard, clk + AB::Expr::from_canonical_u8(4),
         local.sp - AB::Expr::from_canonical_u8(4), &local.op_res_access, local.selectors.is_localget+local.selectors.is_i32const);
         
        
        let is_store_instruciton = self.is_store_instruction::<AB>(&local.selectors);
        // make sure the result is correclty write into memory
        builder.when(AB::Expr::one()-is_store_instruciton-local.selectors.is_localset-local.selectors.is_localtee).assert_word_eq(local.res, *local.op_res_access.value());
        builder.when(local.instruction.is_binary).assert_word_eq(local.op_arg2, *local.op_arg2_access.value());

    }

    pub(crate) fn eval_alu_ops<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        local: &CpuCols<AB::Var>,
    ){
        let is_ordinary_alu_instruction: AB::Expr = self.is_ordinary_alu_instruction::<AB>(&local.selectors);
        let is_comparison_alu_instruction: AB::Expr  = self.is_comparision_alu_instruction::<AB>(&local.selectors);
         // oridnary ALU instructions.
         builder.send_alu(
            local.instruction.opcode,
            local.op_res_val(),
            local.op_arg1_val(),
            local.op_arg2_val(),
            local.shard,
            local.nonce,
            is_ordinary_alu_instruction,
        );
        let alu_cols = local.opcode_specific_columns.alu();


        
        
        // comparision ALU instruction.
        // we first get the boolean value of a_eq_b a_gt_b and a_lt_b
        // we then use them to prove the correctness of comparision ops.
        builder
            .when(is_comparison_alu_instruction.clone())
            .when(alu_cols.arg1_eq_arg2)
            .assert_word_eq(local.op_arg1_val(),local.op_arg2_val());

        // Calculate a_lt_b <==> a < b (using appropriate signedness).
        let use_signed_comparison = local.selectors.is_i32ges + local.selectors.is_i32gts+
        local.selectors.is_i32les;
        let comparison_alu = local.opcode_specific_columns.alu();

        // assert that all comparison variable are bool
        builder.when(is_comparison_alu_instruction.clone()).assert_bool(comparison_alu.res_bool);
        builder.when(is_comparison_alu_instruction.clone()).assert_bool(comparison_alu.arg1_eq_arg2);
        builder.when(is_comparison_alu_instruction.clone()).assert_bool(comparison_alu.arg1_gt_arg2);
        builder.when(is_comparison_alu_instruction.clone()).assert_bool(comparison_alu.arg1_lt_arg2);
        builder.send_alu(
            use_signed_comparison.clone() * Opcode::SLT.as_field::<AB::F>()
                + (AB::Expr::one() - use_signed_comparison.clone())
                    * Opcode::SLTU.as_field::<AB::F>(),
            Word::extend_var::<AB>(comparison_alu.arg1_lt_arg2),
            local.op_arg1_val(),
            local.op_arg2_val(),
            local.shard,
            comparison_alu.a_lt_b_nonce,
            is_comparison_alu_instruction.clone(),
        );

        // Calculate a_gt_b <==> a > b (using appropriate signedness).
        builder.send_alu(
            use_signed_comparison.clone() * Opcode::SLT.as_field::<AB::F>()
                + (AB::Expr::one() - use_signed_comparison) * Opcode::SLTU.as_field::<AB::F>(),
            Word::extend_var::<AB>(comparison_alu.arg1_gt_arg2),
            local.op_arg2_val(),
            local.op_arg1_val(),
            local.shard,
            comparison_alu.a_gt_b_nonce,
            is_comparison_alu_instruction.clone(),
        );
        
        builder
        .when(((local.selectors.is_i32gts+local.selectors.is_i32gtu) 
            * comparison_alu.res_bool )
            +(local.selectors.is_i32les+local.selectors.is_i32leu)
            *(AB::Expr::one()-comparison_alu.res_bool))
        .assert_one(comparison_alu.arg1_gt_arg2);
       
        builder
        .when(((local.selectors.is_i32gts+local.selectors.is_i32gtu) 
            *(AB::Expr::one()-comparison_alu.res_bool))
            +(local.selectors.is_i32les+local.selectors.is_i32leu)
            *comparison_alu.res_bool )
        .assert_one(comparison_alu.arg1_lt_arg2+comparison_alu.arg1_eq_arg2);
               
        builder
        .when((local.selectors.is_i32ges+local.selectors.is_i32geu)
            *comparison_alu.res_bool)
        .assert_one(comparison_alu.arg1_gt_arg2+comparison_alu.arg1_eq_arg2);
        
        builder
        .when((local.selectors.is_i32ges+local.selectors.is_i32geu)
            *(AB::Expr::one()-comparison_alu.res_bool))
        .assert_one(comparison_alu.arg1_lt_arg2);   
        
        builder.when(local.selectors.is_i32eq*comparison_alu.res_bool+
            local.selectors.is_i32ne*(AB::Expr::one()-comparison_alu.res_bool))
            .assert_one(comparison_alu.arg1_eq_arg2);
        builder.when(local.selectors.is_i32eq *(AB::Expr::one()-comparison_alu.res_bool) 
        +local.selectors.is_i32ne*comparison_alu.res_bool)
        .assert_one(comparison_alu.arg1_gt_arg2+comparison_alu.arg1_lt_arg2);
        
        builder.when(local.selectors.is_i32eqz).assert_word_zero(local.op_arg2);
        builder.when(local.selectors.is_i32eqz * comparison_alu.res_bool)
        .assert_word_zero(local.op_arg1_val());
        builder.when(local.selectors.is_i32eqz * (AB::Expr::one()-comparison_alu.res_bool))
        .assert_one(comparison_alu.arg1_gt_arg2+comparison_alu.arg1_lt_arg2);
        
    }

}

impl<F> BaseAir<F> for CpuChip {
    fn width(&self) -> usize {
        NUM_CPU_COLS
    }
}
