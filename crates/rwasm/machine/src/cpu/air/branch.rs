use p3_air::AirBuilder;
use p3_field::AbstractField;
use sp1_stark::{
    air::{BaseAirBuilder, SP1AirBuilder},
    Word,
};

use crate::{
    air::WordAirBuilder,
    cpu::{
        columns::{CpuCols, OpcodeSelectorCols},
        CpuChip,
    },
    operations::BabyBearWordRangeChecker,
};

use sp1_rwasm_executor::Opcode;

impl CpuChip {
    /// Computes whether the opcode is a branch instruction.
    pub(crate) fn is_branch_instruction<AB: SP1AirBuilder>(
        &self,
        opcode_selectors: &OpcodeSelectorCols<AB::Var>,
    ) -> AB::Expr {
        opcode_selectors.is_br
        + opcode_selectors.is_brifeqz
        + opcode_selectors.is_brifnez
          
    }

    /// Verifies all the branching related columns.
    ///
    /// It does this in few parts:
    /// 1. It verifies that the next pc is correct based on the branching column.  That column is a
    ///    boolean that indicates whether the branch condition is true.
    /// 2. It verifies the correct value of branching based on the helper bool columns (a_eq_b,
    ///    a_gt_b, a_lt_b).
    /// 3. It verifier the correct values of the helper bool columns based on op_a and op_b.
    pub(crate) fn eval_branch_ops<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        is_branch_instruction: AB::Expr,
        local: &CpuCols<AB::Var>,
        next: &CpuCols<AB::Var>,
    ) {
        // Get the branch specific columns.
        let branch_cols = local.opcode_specific_columns.branch();

        // Evaluate program counter constraints.
        {
            // When we are branching, assert local.pc <==> branch_cols.pc as Word.
            builder.when(local.branching).assert_eq(branch_cols.pc.reduce::<AB>(), local.pc);

            // When we are branching, assert that next.pc <==> branch_columns.next_pc as Word.
            builder
                .when_transition()
                .when(next.is_real)
                .when(local.branching)
                .assert_eq(branch_cols.next_pc.reduce::<AB>(), next.pc);

            // When the current row is real and local.branching, assert that local.next_pc <==>
            // branch_columns.next_pc as Word.
            builder
                .when(local.is_real)
                .when(local.branching)
                .assert_eq(branch_cols.next_pc.reduce::<AB>(), local.next_pc);

            // Range check branch_cols.pc and branch_cols.next_pc.
            BabyBearWordRangeChecker::<AB::F>::range_check(
                builder,
                branch_cols.pc,
                branch_cols.pc_range_checker,
                is_branch_instruction.clone(),
            );
            BabyBearWordRangeChecker::<AB::F>::range_check(
                builder,
                branch_cols.next_pc,
                branch_cols.next_pc_range_checker,
                is_branch_instruction.clone(),
            );

            // When we are branching, calculate branch_cols.next_pc <==> branch_cols.pc + c.
            builder.send_alu(
                Opcode::ADD.as_field::<AB::F>(),
                branch_cols.next_pc,
                branch_cols.pc,
                local.instruction.aux_val,
                local.shard,
                branch_cols.next_pc_nonce,
                local.branching,
            );

            // When we are not branching, assert that local.pc + 4 <==> next.pc.
            builder
                .when_transition()
                .when(next.is_real)
                .when(local.not_branching)
                .assert_eq(local.pc + AB::Expr::from_canonical_u8(4), next.pc);

            // When local.not_branching is true, assert that local.is_real is true.
            builder.when(local.not_branching).assert_one(local.is_real);

            // When the last row is real and local.not_branching, assert that local.pc + 4 <==>
            // local.next_pc.
            builder
                .when(local.is_real)
                .when(local.not_branching)
                .assert_eq(local.pc + AB::Expr::from_canonical_u8(4), local.next_pc);

            // Assert that either we are branching or not branching when the instruction is a
            // branch.
            builder
                .when(is_branch_instruction.clone())
                .assert_one(local.branching + local.not_branching);
            builder.when(is_branch_instruction.clone()).assert_bool(local.branching);
            builder.when(is_branch_instruction.clone()).assert_bool(local.not_branching);
        }

        // Evaluate branching value constraints.
        {
            // When the opcode is BEQ and we are branching, assert that a_eq_b is true.
            builder.when(local.selectors.is_brifeqz * local.branching).assert_one(branch_cols.a_eq_zero);

           

            // When the opcode is BNE and we are branching, assert that either a_gt_b or a_lt_b is
            // true.
            builder
                .when(local.selectors.is_brifnez * local.branching)
                .assert_one(branch_cols.a_gt_zero);

          

        
       
        // When it's a branch instruction and a_eq_b, assert that a == b.
        builder
            .when(is_branch_instruction.clone() * branch_cols.a_eq_zero)
            .assert_word_eq(local.op_arg1_val(), Word::<AB::F>::from(0));

        //  To prevent this ALU send to be arbitrarily large when is_branch_instruction is false.
        builder.when_not(is_branch_instruction.clone()).assert_zero(local.branching);

       

        
        builder.send_alu(
            Opcode::SLTU.as_field::<AB::F>(),
            Word::extend_var::<AB>(branch_cols.a_gt_zero),
            Word::<AB::F>::from(0),
            local.op_arg1_val(),
            local.shard,
            branch_cols.a_gt_b_nonce,
            is_branch_instruction.clone()-local.selectors.is_br,
        );
    }
}
}