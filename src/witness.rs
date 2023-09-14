use ark_ff::PrimeField;
use num_bigint::BigInt;
use num_traits::Signed;
use num_traits::Zero;
use std::io::{Error as IoError, Read};

const BYTES_PER_WORD: usize = 4;
const N32: usize = 8;

fn from_array32(arr: Vec<u32>) -> BigInt {
    let mut res = BigInt::zero();
    let radix = BigInt::from(0x100000000u64);
    for &val in arr.iter() {
        res = res * &radix + BigInt::from(val);
    }
    res
}

pub fn witness_assignments<E: ark_ec::pairing::Pairing, R: Read>(
    wtns: &mut R,
) -> Result<Vec<E::ScalarField>, IoError> {
    let modulus = <E::ScalarField as PrimeField>::MODULUS;

    let mut buffer = [0; BYTES_PER_WORD]; // buffer for reading in u32s

    let mut witness = Vec::new();
    let mut arr = vec![0; N32];
    let mut j: usize = 0;
    while let Ok(()) = wtns.read_exact(&mut buffer) {
        arr[N32 - 1 - j % N32] = u32::from_le_bytes(buffer); // convert BYTES_PER_WORD LE bytes to u32
        j += 1;

        if j % N32 == 0 {
            let w = from_array32(arr.clone()); // convert N32 u32s to BigInt
            let w = if w.sign() == num_bigint::Sign::Minus {
                // Need to negate the witness element if negative
                modulus.into() - w.abs().to_biguint().unwrap()
            } else {
                w.to_biguint().unwrap()
            };
            witness.push(E::ScalarField::from(w));
        }
    }
    Ok(witness)
}
