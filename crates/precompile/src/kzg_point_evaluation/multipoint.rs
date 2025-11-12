//! Implementation of the multipoint evaluation for KZG.

use crate::bls12_381::arkworks::pairing_check;
use crate::PrecompileError;
use ark_bls12_381::{Fr, G1Affine, G2Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, PrimeField};
use ark_serialize::CanonicalDeserialize;
use core::ops::Neg;

/// Verify KZG multipoint evaluation using BLS12-381 implementation.
/// Previous work (Point evaluation)
/// <https://github.com/ethereum/EIPs/blob/4d2a00692bb131366ede1a16eced2b0e25b1bf99/EIPS/eip-4844.md?plain=1#L203>
/// So point evaluation was an eip this might conduct that the multipoint evaluation can turn into one 


//This can be updated but for this PoC it's ok 

pub const MAX_EVALUATION_POINTS: usize = 128;

#[inline]
/// Verify KZG multipoint evaluation proof.
///
/// Verifies that a polynomial commitment is consistent with multiple point evaluations
/// using a single multiproof. This is more gas-efficient than verifying each point separately.
///
/// # Arguments
/// * `commitment` - Compressed G1 point commitment to the polynomial
/// * `z_values` - Array of evaluation points (field elements)
/// * `y_values` - Array of evaluation values (field elements)
/// * `proof` - Compressed G2 point multiproof
/// * `i_tau` - Compressed G1 point commitment to the interpolation polynomial
/// * `z_commit` - Compressed G1 point commitment to the zero polynomial
///
/// # Returns
/// `true` if the proof is valid, `false` otherwise
pub fn verify_kzg_multipoint_proof(
    commitment: &[u8; 48],
    z_values: &[[u8; 32]],
    y_values: &[[u8; 32]],
    proof: &[u8; 96], //Is this cause it's living in the field extension?
    i_tau: &[u8; 48],
    z_commit: &[u8; 48],
) -> bool {

    //Sanity checks

    if z_values.len() != y_values.len() || z_values.is_empty() || z_values.len() > MAX_EVALUATION_POINTS {
        return false;
    };

    //Parse the commitment (G1 point) 
    let Ok(commitment_point) = parse_g1_compressed(commitment) else {
        return false;
    };

    //Proof live in extension field
    let Ok(proof_point) = parse_g2_compressed(proof) else {
        return false;
    };

    let Ok(z_commit_point) = parse_g1_compressed(z_commit) else {
        return false;
    };

    //Parse i_tau as G1 point
    let Ok(i_tau_point) = parse_g1_compressed(i_tau) else {
        return false;
    };

    //Parse the evaluation points 

    for i in 0..z_values.len() {
        if read_scalar_canonical(&z_values[i]).is_err() {
            return false;
        }
        if read_scalar_canonical(&y_values[i]).is_err() {
            return false;
        }
    }

    let commitment_minus_i = p1_sub_affine(&commitment_point, &i_tau_point);

    let g2 = get_g2_generator();
    let commitment_minus_i_neg = p1_neg(&commitment_minus_i);

    pairing_check(&[(z_commit_point, proof_point), (commitment_minus_i_neg, g2)])
}    


/// Parse a G1 point from compressed format (48 bytes)
fn parse_g1_compressed(bytes: &[u8; 48]) -> Result<G1Affine, PrecompileError> {
    G1Affine::deserialize_compressed(&bytes[..]).map_err(|_| PrecompileError::KzgInvalidG1Point)
}

/// Parse a G2 point from compressed format (96 bytes)
fn parse_g2_compressed(bytes: &[u8; 96]) -> Result<G2Affine, PrecompileError> {
    G2Affine::deserialize_compressed(&bytes[..]).map_err(|_| PrecompileError::Bls12381G2NotOnCurve)
}

/// Read a scalar field element from bytes and verify it's canonical
fn read_scalar_canonical(bytes: &[u8; 32]) -> Result<Fr, PrecompileError> {
    let fr = Fr::from_be_bytes_mod_order(bytes);

    // Check if the field element is canonical by serializing back and comparing
    let bytes_roundtrip = fr.into_bigint().to_bytes_be();

    if bytes_roundtrip.as_slice() != bytes {
        return Err(PrecompileError::NonCanonicalFp);
    }

    Ok(fr)
}

/// Get G2 generator point
#[inline]
fn get_g2_generator() -> G2Affine {
    G2Affine::generator()
}

/// Subtract two G1 points in affine form
#[inline]
fn p1_sub_affine(a: &G1Affine, b: &G1Affine) -> G1Affine {
    (a.into_group() - b.into_group()).into_affine()
}

/// Negate a G1 point
#[inline]
fn p1_neg(p: &G1Affine) -> G1Affine {
    p.neg()
}

    


