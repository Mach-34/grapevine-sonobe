use ark_ff::{PrimeField, BigInteger};
use ark_pallas::Fr;
use ark_std::rand::rngs::OsRng;
use std::error::Error;
use num_bigint::{BigInt, Sign::Plus, RandBigInt};

use super::{MAX_SECRET_LENGTH, MAX_USERNAME_LENGTH, SECRET_FIELD_LENGTH};

/** Get the starting ivc inputs (z0) for the grapevine circuit */
pub fn get_z0<F: PrimeField>() -> [F; 4] {
    (0..4).map(|_| F::zero()).collect::<Vec<F>>().try_into().unwrap()
}

/** Generates a random field element for given field as bigint */
pub fn random_f_bigint<F: PrimeField>() -> BigInt {
    let lower_bound = BigInt::from(0);
    let upper_bound = BigInt::from_bytes_be(Plus, &F::MODULUS.to_bytes_be());
    OsRng.gen_bigint_range(&lower_bound, &upper_bound)
}

/**
 * Converts a given word to array of 6 field elements
 * @dev split into 31-byte strings to fit in finite field and pad with 0's where necessary
 *
 * @param phrase - the string entered by user to compute hash for (will be length checked)
 * @return - array of 6 Fr elements
 */
pub fn serialize_phrase(
    phrase: &String,
) -> Result<[BigInt; SECRET_FIELD_LENGTH], Box<dyn Error>> {
    // check length
    if phrase.len() > MAX_SECRET_LENGTH {
        return Err("Phrase must be <= 180 characters".into());
    }
    // convert each 31-byte chunk to field element
    let mut chunks: [BigInt; SECRET_FIELD_LENGTH] = Default::default();
    for i in 0..SECRET_FIELD_LENGTH {
        // get the range
        let start = i * 31;
        let end = (i + 1) * 31;
        let mut chunk: [u8; 32] = [0; 32];
        // select slice from range and pad if needed
        if start >= phrase.len() {
        } else if end > phrase.len() {
            chunk[1..(phrase.len() - start + 1)].copy_from_slice(&phrase.as_bytes()[start..]);
        } else {
            chunk[1..32].copy_from_slice(&phrase.as_bytes()[start..end]);
        }
        // wrap in field element
        chunks[i] = BigInt::from_bytes_be(Plus, &chunk);
    }
    Ok(chunks)
}

/**
* Converts a given username to a field element
*
* @param username - the username to convert to utf8 and into field element
* @return - the username serialied into the field element
*/
pub fn serialize_username(username: &String) -> Result<BigInt, Box<dyn Error>> {
    // check length
    if username.len() > MAX_USERNAME_LENGTH {
        return Err("Username must be <= 30 characters".into());
    }
    // convert to big endian bytes
    let mut bytes: [u8; 32] = [0; 32];
    bytes[1..(username.len() + 1)].copy_from_slice(&username.as_bytes()[..]);
    // convert to bigint
    Ok(BigInt::from_bytes_be(Plus, &bytes))
}
