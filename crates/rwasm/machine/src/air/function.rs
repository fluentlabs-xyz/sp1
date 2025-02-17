use std::iter::once;

use p3_air::AirBuilder;
use sp1_stark::{
    air::{AirInteraction, BaseAirBuilder, InteractionScope},
    InteractionKind,
};

use crate::{
    cpu::columns::{InstructionCols, OpcodeSelectorCols},
    function,
};

/// A trait which contains methods related to program interactions in an AIR.
pub trait FuncCallAirBuilder: BaseAirBuilder {
    /// Sends an instruction.
    fn send_function_call(
        &mut self,
        pc: impl Into<Self::Expr>,
        function: impl Into<Self::Expr>,
        index_by_function: impl Into<Self::Expr>,
        depth: impl Into<Self::Expr>,
        shard: impl Into<Self::Expr> + Copy,
        multiplicity: impl Into<Self::Expr>,
    ) {
        let values = once(pc.into())
            .chain(once(function.into()))
            .chain(once(index_by_function.into()))
            .chain(once(depth.into()))
            .chain(once(shard.into()))
            .collect();

        self.send(
            AirInteraction::new(values, multiplicity.into(), InteractionKind::Funccall),
            InteractionScope::Local,
        );
    }

    /// Receives an instruction.
    fn receive_function_call(
        &mut self,
        pc: impl Into<Self::Expr>,
        function: impl Into<Self::Expr>,
        index_by_function: impl Into<Self::Expr>,
        depth: impl Into<Self::Expr>,
        shard: impl Into<Self::Expr> + Copy,
        multiplicity: impl Into<Self::Expr>,
    ) {
        let values: Vec<<Self as AirBuilder>::Expr> = once(pc.into())
            .chain(once(function.into()))
            .chain(once(index_by_function.into()))
            .chain(once(depth.into()))
            .chain(once(shard.into()))
            .collect();

        self.receive(
            AirInteraction::new(values, multiplicity.into(), InteractionKind::Funccall),
            InteractionScope::Local,
        );
    }
}
