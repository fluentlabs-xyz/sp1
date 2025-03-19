use sp1_derive::AlignedBorrow;
use sp1_stark::Word;
use std::mem::size_of;

use crate::operations::BabyBearWordRangeChecker;

pub const NUM_AUIPC_COLS: usize = size_of::<FunccallCols<u8>>();

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct FunccallCols<T> {
    pub return_depth_is_not_zero:T,
    pub depth_is_zero:T,
    pub dropkeep_is_one:T,
}
