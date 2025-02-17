use serde::{Deserialize, Serialize};

use crate::Instruction;

use super::{memory::MemoryRecordEnum, LookupId, MemoryReadRecord, MemoryWriteRecord};


#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct FunctionEvent{
    pub shard :u32,
    pub detph :u32,
    pub return_pc : u32,
    pub kind:FunctionEventKind,
}
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub enum FunctionEventKind{
    FunctinonCallInternal = 1,
    FunctionReturnInternal = 2,
}
