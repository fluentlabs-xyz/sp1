mod air;

pub use air::*;

#[cfg(test)]
mod tests {

    use rwasm_executor::Program;
    use sp1_curves::{params::FieldParameters, uint256::U256Field, utils::biguint_from_limbs};
    use sp1_stark::CpuProver;
    

    use crate::{
        io::SP1Stdin,
        utils::{self, run_test},
    };

  
    #[test]
    fn test_uint256_modulus() {
        assert_eq!(biguint_from_limbs(U256Field::MODULUS), U256Field::modulus());
    }
}
