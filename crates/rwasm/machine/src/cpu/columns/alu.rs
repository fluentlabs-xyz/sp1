use sp1_derive::AlignedBorrow;
use sp1_stark::Word;
use std::mem::size_of;

use crate::operations::BabyBearWordRangeChecker;

pub const NUM_AUIPC_COLS: usize = size_of::<AluCols<u8>>();

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct AluCols<T> {
     /// Whether a equals b.
     pub arg1_eq_arg2: T,

     /// Whether a is greater than b.
     pub arg1_gt_arg2: T,
 
     /// Whether a is less than b.
     pub arg1_lt_arg2: T, 
     
     /// The comparision result. gurantee to be bool
     pub res_bool:T,
    // The nounce of the comparision event
    pub a_lt_b_nonce:T,
    // The nounce of the comparision event
    pub a_gt_b_nonce:T,
}
