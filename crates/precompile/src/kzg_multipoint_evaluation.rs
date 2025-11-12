//! KZG multipoint evaluation precompile
//! For more details check [`run`] function.
use crate::{
    crypto, Address, Precompile, PrecompileError, PrecompileId, PrecompileOutput, PrecompileResult,
};

// Import multipoint implementation from kzg_point_evaluation module
use crate::kzg_point_evaluation::multipoint;

/// Address of the KZG multipoint evaluation precompile.
/// 0x12 was the next available address after 0x11 (BLS12 Map FP2 to G2)
pub const ADDRESS: Address = crate::u64_to_address(0x12);

/// Gas cost of the KZG multipoint evaluation precompile.
/// TODO: Adjust based on the actual gas cost specification
pub const GAS_COST: u64 = 50_000;

/// KZG multipoint evaluation precompile, containing address and function to run.
pub const MULTIPOINT_EVALUATION: Precompile =
    Precompile::new(PrecompileId::KzgMultipointEvaluation, ADDRESS, run);

/// Run kzg multipoint evaluation precompile.
///
/// TODO: Implement the multipoint evaluation logic
/// The input format and verification logic need to be defined based on the specification.
pub fn run(input: &[u8], gas_limit: u64) -> PrecompileResult {
    if gas_limit < GAS_COST {
        return Err(PrecompileError::OutOfGas);
    }

    // TODO: Implement the multipoint evaluation logic
    // Verify input length, parse inputs, verify proofs, etc.

    Ok(PrecompileOutput::new(GAS_COST, &[]))
}


