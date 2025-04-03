//! An implementation of an exucutor for the SP1 RISC-V zkVM.

#![warn(clippy::pedantic)]
#![allow(clippy::similar_names)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::cast_lossless)]
#![allow(clippy::bool_to_int_with_if)]
#![allow(clippy::should_panic_without_expect)]
#![allow(clippy::field_reassign_with_default)]
#![allow(clippy::manual_assert)]
#![allow(clippy::unreadable_literal)]
#![allow(clippy::match_wildcard_for_single_variants)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::explicit_iter_loop)]
#![allow(clippy::struct_excessive_bools)]
#![warn(missing_docs)]

mod air;
mod context;
mod cost;
mod dependencies;
pub mod estimator;
pub mod events;
mod executor;
mod hook;
mod io;
mod memory;
mod opcode;
#[cfg(feature = "profiling")]
mod profiler;
mod program;
mod record;
mod reduce;
mod report;
mod state;
pub mod subproof;
pub mod syscalls;
mod utils;

pub use air::*;
pub use context::*;
pub use cost::*;
pub use executor::*;
pub use hook::*;
pub use opcode::*;
pub use program::*;
pub use record::*;
pub use reduce::*;
pub use report::*;
pub use state::*;
pub use utils::*;
