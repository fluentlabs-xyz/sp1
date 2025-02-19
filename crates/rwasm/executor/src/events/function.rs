use serde::{Deserialize, Serialize};

use crate::Instruction;

use super::{memory::MemoryRecordEnum, LookupId, MemoryReadRecord, MemoryWriteRecord};

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct FunccallEvent {
    pub shard: u32,
    pub detph: u32,
    pub return_pc: u32,
    pub kind: FunccallEventKind,
    pub func_index: u32,
    pub func_pc_by_index: u32,
}
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub enum FunccallEventKind {
    FunctinonCallInternal = 1,
    FunctionReturnInternal = 2,
}
