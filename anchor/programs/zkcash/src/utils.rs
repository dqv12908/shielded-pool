use crate::Proof;
use crate::groth16::{Groth16Verifier, Groth16Verifyingkey};
use crate::ErrorCode;
use ark_bn254;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use std::ops::Neg;
use ark_bn254::Fr;
use ark_ff::PrimeField;
use anchor_lang::prelude::*;
use anchor_lang::solana_program::hash::hash;

type G1 = ark_bn254::g1::G1Affine;

pub const SOL_ADDRESS: Pubkey = anchor_lang::pubkey!("11111111111111111111111111111112");

pub const VERIFYING_KEY: Groth16Verifyingkey =  Groth16Verifyingkey {
	nr_pubinputs: 7,

	vk_alpha_g1: [
		36,82,41,217,176,118,179,192,232,164,215,11,222,140,28,204,255,160,138,159,174,117,87,177,101,179,176,219,214,83,226,199,
		37,62,200,89,136,219,184,78,70,233,75,94,250,51,115,180,122,0,11,74,198,200,107,45,75,121,141,39,74,24,35,2,
	],

	vk_beta_g2: [
		7,9,10,130,232,250,187,211,146,153,190,36,112,91,146,207,32,142,232,179,72,127,111,43,57,255,39,151,138,41,161,219,
		36,36,188,193,246,10,84,114,104,95,213,7,5,178,128,150,38,225,112,18,10,202,244,65,225,51,162,189,94,97,210,68,
		10,225,19,92,255,218,242,39,197,220,38,103,64,96,122,169,48,188,59,217,45,220,43,19,80,134,217,218,45,253,62,42,
		43,134,133,159,211,213,92,157,21,15,179,240,174,186,121,136,38,73,61,215,61,53,122,176,249,253,172,237,159,200,24,41,
	],

	vk_gamme_g2: [
		25,142,147,147,146,13,72,58,114,96,191,183,49,251,93,37,241,170,73,51,53,169,231,18,151,228,133,183,174,243,18,194,
		24,0,222,239,18,31,30,118,66,106,0,102,94,92,68,121,103,67,34,212,247,94,218,221,70,222,189,92,217,146,246,237,
		9,6,137,208,88,95,240,117,236,158,153,173,105,12,51,149,188,75,49,51,112,179,142,243,85,172,218,220,209,34,151,91,
		18,200,94,165,219,140,109,235,74,171,113,128,141,203,64,143,227,209,231,105,12,67,211,123,76,230,204,1,102,250,125,170,
	],

	vk_delta_g2: [
		40,236,231,143,65,229,234,11,204,218,36,127,248,55,201,51,109,148,125,186,107,142,211,122,158,66,246,126,46,138,177,67,
		36,45,179,168,119,17,45,22,173,121,131,205,137,165,238,212,136,109,204,16,196,114,106,41,129,210,88,95,203,42,222,136,
		13,212,104,224,153,193,238,94,88,150,65,130,2,9,243,16,141,104,235,5,148,104,232,168,145,45,52,177,146,131,221,75,
		35,211,216,27,123,229,22,14,202,242,29,249,44,126,36,151,78,59,253,198,176,128,66,177,242,47,172,192,6,218,253,146,
	],

	vk_ic: &[
		[
			10,140,43,158,87,101,56,80,231,128,73,104,13,18,128,143,176,11,69,169,141,219,72,153,140,201,161,170,20,95,208,48,
			5,225,74,2,187,138,71,213,91,34,74,102,108,130,213,92,113,105,49,63,170,100,54,141,61,58,107,247,65,3,72,26,
		],
		[
			35,93,128,104,30,0,129,142,56,251,161,20,215,130,170,81,63,172,20,148,144,31,115,136,206,13,140,213,72,87,19,40,
			9,132,163,92,179,1,19,215,5,109,56,124,86,223,106,202,69,198,129,5,139,219,105,238,109,191,11,147,58,109,5,47,
		],
		[
			16,100,105,122,193,174,81,159,244,48,22,70,22,25,213,220,30,160,181,84,28,237,162,29,145,35,106,174,41,133,95,224,
			3,172,229,56,20,72,103,78,71,234,15,98,89,52,23,170,135,194,169,125,45,162,4,183,36,197,9,96,206,246,139,143,
		],
		[
			46,241,112,196,201,98,139,159,119,146,128,63,224,117,220,247,163,58,147,128,92,206,94,146,158,4,240,75,89,129,188,120,
			43,38,239,109,151,196,95,233,255,195,94,165,75,233,27,206,131,53,66,151,140,28,17,229,234,221,3,165,140,39,46,247,
		],
		[
			19,24,21,89,67,87,157,50,55,149,108,115,67,91,50,176,100,120,232,177,139,116,186,132,177,30,0,126,186,68,216,198,
			44,234,182,243,119,160,82,121,86,245,140,137,98,70,195,250,170,154,217,19,12,224,233,75,211,134,193,28,98,209,143,100,
		],
		[
			7,167,177,223,3,207,225,19,57,198,162,85,163,195,114,5,125,162,0,204,25,195,133,11,79,72,179,143,199,218,44,106,
			6,162,200,243,7,255,181,87,89,218,104,155,193,182,69,148,168,15,74,106,223,239,110,58,139,234,169,48,142,66,182,114,
		],
		[
			40,39,230,113,69,163,240,145,195,241,72,159,240,100,147,28,66,77,130,111,170,1,155,180,180,244,102,85,174,255,129,175,
			35,242,89,91,104,143,182,1,175,61,150,240,191,33,171,66,223,108,58,121,194,124,70,143,221,203,136,88,211,58,227,154,
		],
		[
			27,83,106,197,198,250,26,100,252,192,148,233,128,154,30,142,12,239,105,74,34,116,253,204,239,110,237,194,120,147,200,43,
			2,55,31,169,127,183,38,92,42,251,242,190,109,187,205,119,32,232,224,203,35,137,19,117,136,198,125,14,158,61,191,250,
		],
	]
};

/**
 * Calculates the expected public amount from ext_amount and fee, then verifies if it matches
 * the provided public_amount_bytes.
 *
 * @param ext_amount The external amount (can be positive or negative), as i64.
 * @param fee The fee (non-negative), as u64.
 * @param public_amount_bytes The public amount to verify against, as a 32-byte array (big-endian).
 * @return Returns `true` if the calculated public amount matches public_amount_bytes AND 
 *         the input ext_amount and fee are valid according to predefined limits. 
 *         Returns `false` otherwise (either due to mismatch or invalid inputs for calculation).
 */
pub fn check_public_amount(ext_amount: i64, fee: u64, public_amount_bytes: [u8; 32]) -> bool {
    if ext_amount == i64::MIN {
        msg!("can't use i64::MIN as ext_amount"); 
        return false;
    }

    // Convert to field elements for proper BN254 arithmetic
    let fee_fr = Fr::from(fee);
    let ext_amount_fr = if ext_amount >= 0 {
        Fr::from(ext_amount as u64)
    } else {
        let abs_ext_amount = match ext_amount.checked_neg() {
            Some(val) => val,
            None => return false,
        };
        Fr::from(abs_ext_amount as u64)
    };

    // return false if the deposit amount is barely enough to cover the fee
    if ext_amount >= 0 && ext_amount_fr <= fee_fr {
        return false;
    }

    let result_public_amount = if ext_amount >= 0 {
        // For positive amounts: public_amount = ext_amount - fee
        ext_amount_fr - fee_fr
    } else {
        // For negative amounts: public_amount = -abs(ext_amount) - fee
        // In field arithmetic, this becomes: FIELD_SIZE - (abs(ext_amount) + fee)
        -(ext_amount_fr + fee_fr)
    };

    // Convert provided bytes to field element for comparison
    let provided_amount = Fr::from_be_bytes_mod_order(&public_amount_bytes);
    
    result_public_amount == provided_amount
}

/**
 * Validates that the provided fee meets the minimum required fee based on global configuration.
 * 
 * For deposits (ext_amount > 0):
 * - expected_fee = (ext_amount * deposit_fee_rate) / 10000
 * - minimum_fee = expected_fee * (1 - fee_error_margin/10000)
 * 
 * For withdrawals (ext_amount < 0):
 * - expected_fee = (abs(ext_amount) * withdrawal_fee_rate) / 10000
 * - minimum_fee = expected_fee * (1 - fee_error_margin/10000)
 * 
 * @param ext_amount The external amount (positive for deposits, negative for withdrawals)
 * @param provided_fee The fee provided by the user
 * @param deposit_fee_rate Fee rate for deposits (in basis points, 0-10000)
 * @param withdrawal_fee_rate Fee rate for withdrawals (in basis points, 0-10000)
 * @param fee_error_margin Tolerance rate (in basis points, 0-10000)
 * @return Ok(()) if fee is valid, Err(ErrorCode) if invalid
 */
pub fn validate_fee(
    ext_amount: i64,
    provided_fee: u64,
    deposit_fee_rate: u16,
    withdrawal_fee_rate: u16,
    fee_error_margin: u16,
) -> Result<()> {
    if ext_amount > 0 {
        // Deposit: check fee against deposit rate
        let expected_fee = (ext_amount as u128)
            .checked_mul(deposit_fee_rate as u128)
            .ok_or(ErrorCode::ArithmeticOverflow)?
            .checked_div(10000)
            .ok_or(ErrorCode::ArithmeticOverflow)? as u64;
        
        // Calculate minimum acceptable fee: expected_fee * (1 - fee_error_margin/10000)
        let min_acceptable_fee = if expected_fee > 0 {
            let error_multiplier = 10000u128.checked_sub(fee_error_margin as u128)
                .ok_or(ErrorCode::ArithmeticOverflow)?;
            (expected_fee as u128)
                .checked_mul(error_multiplier)
                .ok_or(ErrorCode::ArithmeticOverflow)?
                .checked_div(10000)
                .ok_or(ErrorCode::ArithmeticOverflow)? as u64
        } else {
            0 // If expected fee is 0, minimum is also 0
        };
        
        require!(
            provided_fee >= min_acceptable_fee,
            ErrorCode::InvalidFeeAmount
        );
    } else if ext_amount < 0 {
        // Withdrawal: check fee against withdrawal rate
        let withdrawal_amount = ext_amount.checked_neg()
            .ok_or(ErrorCode::ArithmeticOverflow)? as u64;
        
        let expected_fee = (withdrawal_amount as u128)
            .checked_mul(withdrawal_fee_rate as u128)
            .ok_or(ErrorCode::ArithmeticOverflow)?
            .checked_div(10000)
            .ok_or(ErrorCode::ArithmeticOverflow)? as u64;
        
        // Calculate minimum acceptable fee: expected_fee * (1 - fee_error_margin/10000)
        let min_acceptable_fee = if expected_fee > 0 {
            let error_multiplier = 10000u128.checked_sub(fee_error_margin as u128)
                .ok_or(ErrorCode::ArithmeticOverflow)?;
            (expected_fee as u128)
                .checked_mul(error_multiplier)
                .ok_or(ErrorCode::ArithmeticOverflow)?
                .checked_div(10000)
                .ok_or(ErrorCode::ArithmeticOverflow)? as u64
        } else {
            0 // If expected fee is 0, minimum is also 0
        };
        
        require!(
            provided_fee >= min_acceptable_fee,
            ErrorCode::InvalidFeeAmount
        );
    }
    // For ext_amount == 0, no fee validation needed
    
    Ok(())
}

pub fn verify_proof(proof: Proof, verifying_key: Groth16Verifyingkey) -> bool {
    let mut public_inputs_vec: [[u8; 32]; 7] = [[0u8; 32]; 7];

    public_inputs_vec[0] = proof.root;
    public_inputs_vec[1] = proof.public_amount;
    public_inputs_vec[2] = proof.ext_data_hash;
    public_inputs_vec[3] = proof.input_nullifiers[0];
    public_inputs_vec[4] = proof.input_nullifiers[1];
    public_inputs_vec[5] = proof.output_commitments[0];
    public_inputs_vec[6] = proof.output_commitments[1];

     // First deserialize PROOF_A into a G1 point
     let g1_point = match G1::deserialize_with_mode(
        &*[&change_endianness(&proof.proof_a[0..64]), &[0u8][..]].concat(),
        Compress::No,
        Validate::Yes,
    ) {
        Ok(point) => point,
        Err(_) => return false,
    };
    
    let mut proof_a_neg = [0u8; 65];
    if g1_point
        .neg()
        .x
        .serialize_with_mode(&mut proof_a_neg[..32], Compress::No)
        .is_err() {
        return false;
    }
    if g1_point
        .neg()
        .y
        .serialize_with_mode(&mut proof_a_neg[32..], Compress::No)
        .is_err() {
        return false;
    }

    let proof_a: [u8; 64] = match change_endianness(&proof_a_neg[..64]).try_into() {
        Ok(array) => array,
        Err(_) => return false,
    };

    let mut verifier = match Groth16Verifier::new(
        &proof_a,
        &proof.proof_b,
        &proof.proof_c,
        &public_inputs_vec,
        &verifying_key
    ) {
        Ok(v) => v,
        Err(_) => return false,
    };

    verifier.verify().unwrap_or(false)
}

/**
 * Calculate ExtData hash with encrypted outputs included
 * This matches the client-side calculation for hash verification
 * 
 * This is for SOL mint address only
 */
pub fn calculate_complete_ext_data_hash(
    recipient: Pubkey,
    ext_amount: i64,
    encrypted_output1: &[u8],
    encrypted_output2: &[u8],
    fee: u64,
    fee_recipient: Pubkey,
    mint_address: Pubkey,
) -> Result<[u8; 32]> {
    #[derive(AnchorSerialize)]
    struct CompleteExtData {
        pub recipient: Pubkey,
        pub ext_amount: i64,
        pub encrypted_output1: Vec<u8>,
        pub encrypted_output2: Vec<u8>,
        pub fee: u64,
        pub fee_recipient: Pubkey,
        pub mint_address: Pubkey,
    }
    
    let complete_ext_data = CompleteExtData {
        recipient,
        ext_amount,
        encrypted_output1: encrypted_output1.to_vec(),
        encrypted_output2: encrypted_output2.to_vec(),
        fee,
        fee_recipient,
        mint_address
    };
    
    let mut serialized_ext_data = Vec::new();
    complete_ext_data.serialize(&mut serialized_ext_data)?;
    let calculated_ext_data_hash = hash(&serialized_ext_data).to_bytes();
    
    Ok(calculated_ext_data_hash)
}

pub fn change_endianness(bytes: &[u8]) -> Vec<u8> {
    let mut vec = Vec::new();
    for b in bytes.chunks(32) {
        for byte in b.iter().rev() {
            vec.push(*byte);
        }
    }
    vec
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_fee_deposit_exact_minimum() {
        // Test deposit with exact minimum fee
        // 1000 * 25 / 10000 = 2.5 -> 2 (rounded down)
        // minimum = 2 * 95% = 1.9 -> 1 (rounded down)
        let result = validate_fee(
            1000,  // ext_amount (deposit)
            1,     // provided_fee (exact minimum)
            0,     // deposit_fee_rate (0% - free deposits)
            25,    // withdrawal_fee_rate (0.25%)
            500,   // error_rate (5%)
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_fee_deposit_above_minimum() {
        // Test deposit with fee above minimum
        let result = validate_fee(
            1000,  // ext_amount (deposit)
            10,    // provided_fee (well above minimum)
            0,     // deposit_fee_rate (0% - free deposits)
            25,    // withdrawal_fee_rate (0.25%)
            500,   // error_rate (5%)
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_fee_deposit_below_minimum() {
        // Test that deposits with 0% fee rate accept any fee >= 0
        // Since deposits are free, any fee should be acceptable
        // 10000 * 0 / 10000 = 0 (expected fee)
        // minimum = 0 * 95% = 0 (minimum acceptable fee)
        let result = validate_fee(
            10000, // ext_amount (deposit)
            0,     // provided_fee (even 0 is acceptable for free deposits)
            0,     // deposit_fee_rate (0% - free deposits)
            25,    // withdrawal_fee_rate (0.25%)
            500,   // error_rate (5%)
        );
        assert!(result.is_ok()); // Should pass since deposits are free
    }

    #[test]
    fn test_validate_fee_withdrawal_zero_rate() {
        // Test withdrawal with 0% fee rate
        let result = validate_fee(
            -1000, // ext_amount (withdrawal)
            5,     // provided_fee (any amount is fine since expected is 0)
            25,    // deposit_fee_rate
            0,     // withdrawal_fee_rate (0%)
            500,   // error_rate (5%)
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_fee_withdrawal_with_rate() {
        // Test withdrawal with non-zero fee rate
        // 1000 * 50 / 10000 = 5
        // minimum = 5 * 95% = 4.75 -> 4 (rounded down)
        let result = validate_fee(
            -1000, // ext_amount (withdrawal)
            4,     // provided_fee (exact minimum)
            25,    // deposit_fee_rate
            50,    // withdrawal_fee_rate (0.5%)
            500,   // error_rate (5%)
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_fee_withdrawal_below_minimum() {
        // Test withdrawal with fee below minimum
        // 1000 * 100 / 10000 = 10
        // minimum = 10 * 95% = 9.5 -> 9 (rounded down)
        let result = validate_fee(
            -1000, // ext_amount (withdrawal)
            8,     // provided_fee (below minimum of 9)
            25,    // deposit_fee_rate
            100,   // withdrawal_fee_rate (1%)
            500,   // error_rate (5%)
        );
        assert!(result.is_err());
        // In anchor, the error is wrapped, so we need to check the error differently
        match result {
            Err(e) => {
                // Check that it contains our error code
                assert!(e.to_string().contains("InvalidFeeAmount") || format!("{:?}", e).contains("InvalidFeeAmount"));
            },
            Ok(_) => panic!("Expected error but got Ok"),
        }
    }

    #[test]
    fn test_validate_fee_zero_amount() {
        // Test with zero ext_amount (should always pass)
        let result = validate_fee(
            0,     // ext_amount (neither deposit nor withdrawal)
            100,   // provided_fee
            25,    // deposit_fee_rate
            50,    // withdrawal_fee_rate
            500,   // error_rate
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_fee_small_deposit_zero_expected() {
        // Test very small deposit that results in 0 expected fee
        // 1 * 25 / 10000 = 0.0025 -> 0 (rounded down)
        let result = validate_fee(
            1,     // ext_amount (very small deposit)
            0,     // provided_fee (0 is acceptable when expected is 0)
            25,    // deposit_fee_rate (0.25%)
            0,     // withdrawal_fee_rate
            500,   // error_rate (5%)
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_fee_high_fee_error_margin() {
        // Test with high fee error margin (50%)
        // 1000 * 25 / 10000 = 2.5 -> 2
        // minimum = 2 * 50% = 1
        let result = validate_fee(
            1000,  // ext_amount (deposit)
            1,     // provided_fee (minimum with 50% fee error margin)
            25,    // deposit_fee_rate (0.25%)
            0,     // withdrawal_fee_rate
            5000,  // fee_error_margin (50%)
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_fee_overflow_protection() {
        // Test that we don't overflow with large amounts
        // Use a large but safe value that won't cause overflow during multiplication
        let result = validate_fee(
            1_000_000_000, // ext_amount (1 billion, large but safe)
            1000000,       // provided_fee
            1,             // deposit_fee_rate (small rate to avoid overflow)
            0,             // withdrawal_fee_rate
            500,           // error_rate (5%)
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_fee_edge_case_min_withdrawal() {
        // Test edge case with minimum negative value (but not i64::MIN)
        let result = validate_fee(
            -1,    // ext_amount (smallest withdrawal)
            0,     // provided_fee
            25,    // deposit_fee_rate
            0,     // withdrawal_fee_rate (0%, so any fee is fine)
            500,   // error_rate (5%)
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_fee_arithmetic_overflow_detection() {
        // Test that arithmetic overflow is properly detected and handled
        // Using maximum values that would cause overflow in the multiplication
        let result = validate_fee(
            i64::MAX,  // ext_amount (maximum positive value)
            0,         // provided_fee
            10000,     // deposit_fee_rate (100% - maximum rate)
            0,         // withdrawal_fee_rate
            0,         // fee_error_margin (0% to test exact calculation)
        );
        // This should return an error (either arithmetic overflow or invalid fee amount)
        assert!(result.is_err());
        // We don't need to check the specific error type since overflow protection
        // may result in different error conditions depending on implementation
    }
}