//! KZG multipoint evaluation precompile.
//!
//! While point evaluation was added in [`EIP-4844`](https://eips.ethereum.org/EIPS/eip-4844),
//! there's no implementation for multipoint evaluation. This is much needed because if we want
//! to query multiple points we will end spawning the precompile for each point, translating
//! this to a consumption of 50k gas per call
//!
//! For more details check [`run`] function.
use crate::{
    Address, Precompile, PrecompileError, PrecompileId, PrecompileOutput, PrecompileResult,
};
use crate::kzg_point_evaluation::{kzg_to_versioned_hash, multipoint};
use primitives::hex_literal::hex;

/// KZG multipoint evaluation precompile, containing address and function to run.
pub const MULTIPOINT_EVALUATION: Precompile =
    Precompile::new(PrecompileId::KzgMultipointEvaluation, ADDRESS, run);

/// Address of the KZG multipoint evaluation precompile.
pub const ADDRESS: Address = crate::u64_to_address(0x0B);

/// Gas cost of the KZG multipoint evaluation precompile.
pub const GAS_COST: u64 = 50_000;

/// Blobs spec
pub const RETURN_VALUE: &[u8; 64] = &hex!(
    "0000000000000000000000000000000000000000000000000000000000001000"
    "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001"
);

/// Run KZG multipoint evaluation precompile.
///
/// The input is encoded as follows:
/// | versioned_hash | commitment | num_points | z_values | y_values | i_tau | z_commit | proof |
/// |     32         |     48     |     32     | n*32     |   n*32   |   48  |    48    |   96  |
///
/// Where:
/// - `versioned_hash` - 32 bytes, versioned hash of the commitment
/// - `commitment` - 48 bytes, compressed G1 point
/// - `num_points` - 32 bytes, big-endian number of evaluation points (n)
/// - `z_values` - n * 32 bytes, array of evaluation points z_i
/// - `y_values` - n * 32 bytes, array of evaluation values y_i
/// - `i_tau` - 48 bytes, [I(τ)]₁ (compressed G1)
/// - `z_commit` - 48 bytes, commitment to zero polynomial (compressed G1)
/// - `proof` - 96 bytes, multiproof π = [q(τ)]₂ (compressed G2)
pub fn run(input: &[u8], gas_limit: u64) -> PrecompileResult {
    // Minimum input length: versioned_hash (32) + commitment (48) + num_points (32) + i_tau (48) + z_commit (48) + proof (96) = 304
    if input.len() < 304 {
        return Err(PrecompileError::BlobInvalidInputLength);
    }

    // Parse versioned_hash
    let versioned_hash = &input[0..32];
    
    // Parse commitment
    let commitment = &input[32..80];
    if kzg_to_versioned_hash(commitment) != versioned_hash {
        return Err(PrecompileError::BlobMismatchedVersion);
    }

    // Parse num_points (32 bytes, big-endian)
    let num_points_bytes = &input[80..112];
    let num_points = u32::from_be_bytes(
        num_points_bytes[28..32]
            .try_into()
            .map_err(|_| PrecompileError::BlobInvalidInputLength)?,
    ) as usize;

    // Validate number of points
    if num_points == 0 || num_points > multipoint::MAX_EVALUATION_POINTS {
        return Err(PrecompileError::BlobInvalidInputLength);
    }

    // Calculate expected input length
    // 32 (versioned_hash) + 48 (commitment) + 32 (num_points) + num_points*32 (z_values) + num_points*32 (y_values) + 48 (i_tau) + 48 (z_commit) + 96 (proof)
    let expected_len = 304 + (num_points * 64);
    if input.len() != expected_len {
        return Err(PrecompileError::BlobInvalidInputLength);
    }

    // Check gas cost
    if gas_limit < GAS_COST {
        return Err(PrecompileError::OutOfGas);
    }

    // Parse z_values and y_values
    let z_values_start = 112;
    let y_values_start = z_values_start + (num_points * 32);
    let i_tau_start = y_values_start + (num_points * 32);
    let z_commit_start = i_tau_start + 48;
    let proof_start = z_commit_start + 48;

    let mut z_values = Vec::with_capacity(num_points);
    let mut y_values = Vec::with_capacity(num_points);

    for i in 0..num_points {
        let z_start = z_values_start + (i * 32);
        let z_end = z_start + 32;
        let z: [u8; 32] = input[z_start..z_end]
            .try_into()
            .map_err(|_| PrecompileError::BlobInvalidInputLength)?;
        z_values.push(z);

        let y_start = y_values_start + (i * 32);
        let y_end = y_start + 32;
        let y: [u8; 32] = input[y_start..y_end]
            .try_into()
            .map_err(|_| PrecompileError::BlobInvalidInputLength)?;
        y_values.push(y);
    }

    // Parse remaining fields
    let commitment: &[u8; 48] = commitment.try_into().unwrap();
    let i_tau: &[u8; 48] = input[i_tau_start..i_tau_start + 48]
        .try_into()
        .map_err(|_| PrecompileError::BlobInvalidInputLength)?;
    let z_commit: &[u8; 48] = input[z_commit_start..z_commit_start + 48]
        .try_into()
        .map_err(|_| PrecompileError::BlobInvalidInputLength)?;
    let proof: &[u8; 96] = input[proof_start..proof_start + 96]
        .try_into()
        .map_err(|_| PrecompileError::BlobInvalidInputLength)?;

    // Verify multipoint KZG proof
    if !verify_kzg_multipoint_proof(commitment, &z_values, &y_values, proof, i_tau, z_commit) {
        return Err(PrecompileError::BlobVerifyKzgProofFailed);
    }

    // Return FIELD_ELEMENTS_PER_BLOB and BLS_MODULUS as padded 32 byte big endian values
    Ok(PrecompileOutput::new(GAS_COST, RETURN_VALUE.into()))
}

/// Verify KZG multipoint proof.
#[inline]
pub fn verify_kzg_multipoint_proof(
    commitment: &[u8; 48],
    z_values: &[[u8; 32]],
    y_values: &[[u8; 32]],
    proof: &[u8; 96],
    i_tau: &[u8; 48],
    z_commit: &[u8; 48],
) -> bool {
    multipoint::verify_kzg_multipoint_proof(commitment, z_values, y_values, proof, i_tau, z_commit)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Crypto;

    #[test]
    fn test_invalid_input_length() {
        let input = vec![0u8; 100]; // Too short
        let result = run(&input, 100_000);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_num_points() {
        // Create input with num_points = 0
        let mut input = vec![0u8; 304];
        // Set num_points to 0 (last 4 bytes of num_points field)
        input[108..112].copy_from_slice(&[0u8; 4]);
        let result = run(&input, 100_000);
        assert!(result.is_err());
    }

    #[test]
    fn test_multipoint_proof_verification() {
        // Test data generated by running: sage assets/python_impl/testkzg.py
        // The Python script uses a fixed tau (1234567890123456789012345678901234567890) for testing.
        // 
        // Test polynomial: p(X) = 3*x^3 + 2*x^2 + x + 1
        // Evaluation points: [1, 2, 3]
        // Expected evaluations: p(1)=7, p(2)=35 (0x23), p(3)=103 (0x67)
        
        let z_values = &[
            hex!("0000000000000000000000000000000000000000000000000000000000000001"),
            hex!("0000000000000000000000000000000000000000000000000000000000000002"),
            hex!("0000000000000000000000000000000000000000000000000000000000000003"),
        ];
        let y_values = &[
            hex!("0000000000000000000000000000000000000000000000000000000000000007"),
            hex!("0000000000000000000000000000000000000000000000000000000000000023"),
            hex!("0000000000000000000000000000000000000000000000000000000000000067"),
        ];
        
        // Values generated by SageMath script
        let commitment = hex!("abf8c06464ed351a80466654d03d1f94b489a04a297a0f38c30f367cf34fef561c1e2e28969cb5e5e7fc9deee54f6dc7");
        let i_tau = hex!("9438ffa79a133d4f926871ca25433ed5841e2b58dfcbaedc01980297898dc4c33860c07c023652c07cab562655f7ba78");
        let z_commit = hex!("89935a0341bcab4e97800cc7cf78663b1d8e1a2218704189217810d32236f3c46a7d5312c80d2220bbd66da462401895");
        let proof = hex!("89380275bbc8e5dcea7dc4dd7e0550ff2ac480905396eda55062650f8d251c96eb480673937cc6d9d6a44aaa56ca66dc122915c824a0857e2ee414a3dccb23ae691ae54329781315a0c75df1c04d6d7a50a030fc866f09d516020ef82324afae");

        // Test direct verification function
        let result = verify_kzg_multipoint_proof(
            &commitment,
            z_values,
            y_values,
            &proof,
            &i_tau,
            &z_commit,
        );
        
        assert!(result, "Multipoint proof verification should succeed with SageMath-generated test data");
    }

    #[test]
    fn test_multipoint_proof_precompile() {
        // Test data generated by running: sage assets/python_impl/testkzg.py
        // Test polynomial: p(X) = 3*x^3 + 2*x^2 + x + 1
        // Evaluation points: [1, 2, 3]
        // Expected evaluations: p(1)=7, p(2)=35 (0x23), p(3)=103 (0x67)
        
        // Values generated by SageMath script
        let commitment = hex!("abf8c06464ed351a80466654d03d1f94b489a04a297a0f38c30f367cf34fef561c1e2e28969cb5e5e7fc9deee54f6dc7");
        
        // Create versioned hash
        let crypto = &crate::DefaultCrypto;
        let mut versioned_hash = crypto.sha256(&commitment);
        versioned_hash[0] = crate::kzg_point_evaluation::VERSIONED_HASH_VERSION_KZG;

        // num_points = 3 (32 bytes, big-endian, padded)
        let mut num_points = vec![0u8; 32];
        num_points[31] = 3; // Last byte is 3

        let z_values = vec![
            hex!("0000000000000000000000000000000000000000000000000000000000000001"),
            hex!("0000000000000000000000000000000000000000000000000000000000000002"),
            hex!("0000000000000000000000000000000000000000000000000000000000000003"),
        ];

        let y_values = vec![
            hex!("0000000000000000000000000000000000000000000000000000000000000007"),
            hex!("0000000000000000000000000000000000000000000000000000000000000023"),
            hex!("0000000000000000000000000000000000000000000000000000000000000067"),
        ];

        // Values generated by SageMath script
        let i_tau = hex!("9438ffa79a133d4f926871ca25433ed5841e2b58dfcbaedc01980297898dc4c33860c07c023652c07cab562655f7ba78");
        let z_commit = hex!("89935a0341bcab4e97800cc7cf78663b1d8e1a2218704189217810d32236f3c46a7d5312c80d2220bbd66da462401895");
        let proof = hex!("89380275bbc8e5dcea7dc4dd7e0550ff2ac480905396eda55062650f8d251c96eb480673937cc6d9d6a44aaa56ca66dc122915c824a0857e2ee414a3dccb23ae691ae54329781315a0c75df1c04d6d7a50a030fc866f09d516020ef82324afae");

        // Build input: versioned_hash (32) + commitment (48) + num_points (32) + z_values (3*32) + y_values (3*32) + i_tau (48) + z_commit (48) + proof (96)
        let mut input = Vec::new();
        input.extend_from_slice(&versioned_hash);
        input.extend_from_slice(&commitment);
        input.extend_from_slice(&num_points);
        for z in &z_values {
            input.extend_from_slice(z);
        }
        for y in &y_values {
            input.extend_from_slice(y);
        }
        input.extend_from_slice(&i_tau);
        input.extend_from_slice(&z_commit);
        input.extend_from_slice(&proof);

        // Expected gas: fixed 50_000
        let expected_gas = GAS_COST;
        let result = run(&input, expected_gas).unwrap();
        
        assert_eq!(result.gas_used, expected_gas);
        assert_eq!(result.bytes[..], RETURN_VALUE[..]);
    }
}
