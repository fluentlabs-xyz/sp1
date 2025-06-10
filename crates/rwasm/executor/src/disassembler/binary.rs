use std::{fs, path::Path};

use hashbrown::HashMap;

use rwasm::{
    CallStack, ExecutionEngine, ExecutorConfig, RwasmExecutor, RwasmModule, Store, ValueStack,
};

use crate::executor;

pub const FIB_REC_PATH: &str = "../examples/hello/hello.wat";
pub const FIB_PATH: &str = "../examples/hello/hello_copy.wat";
pub const SIMPLE_PATH: &str = "../examples/hello/simple.wat";
pub fn read_wat(file: &Path) -> Vec<u8> {
    let file_bytes = fs::read(file).unwrap();
    let wasm_binary: Vec<u8>;

    wasm_binary = wat::parse_bytes(&file_bytes).unwrap().to_vec();

    wasm_binary
}

pub fn build_rwams_engine<'a>(
    
    store: &'a mut Store<()>,
) -> ExecutionEngine<'a, ()> {
    let config = ExecutorConfig::new();

    let mut engine = ExecutionEngine::new(store);
    engine
}

pub fn build_rwasm_executor<'a>(
    engine: &'a mut ExecutionEngine<()>,
    module: &'a RwasmModule,
) -> RwasmExecutor<'a, ()> {
    let executor =
        RwasmExecutor::new(module, engine.value_stack(), engine.call_stack(), engine.store());
    executor
}
