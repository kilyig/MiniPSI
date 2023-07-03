use ark_ff::{BigInteger, Field, PrimeField};
use ark_std::{test_rng, One, UniformRand, Zero};
use ark_test_curves::bls12_381::Fq as F;

fn main() {
    let mut rng = test_rng();
    let a = F::rand(&mut rng);
    // We can access the prime modulus associated with `F`:
    let modulus = <F as PrimeField>::MODULUS;
    assert_eq!(a.pow(&modulus), a); // the Euler-Fermat theorem tells us: a^{p-1} = 1 mod p
    
    // We can convert field elements to integers in the range [0, MODULUS - 1]:
    let one: num_bigint::BigUint = F::one().into();
    assert_eq!(one, num_bigint::BigUint::one());
    
    // We can construct field elements from an arbitrary sequence of bytes:
    let n = F::from_le_bytes_mod_order(&modulus.to_bytes_le());
    assert_eq!(n, F::zero());
}
