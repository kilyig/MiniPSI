use ark_ff::{Field, PrimeField, BigInteger, BigInt};
// Now we'll use the prime field underlying the BLS12-381 G1 curve.
use ark_test_curves::bls12_381::Fq as F;
use ark_std::{One, Zero, UniformRand};

fn print_type_of<T>(_: &T) {
    println!("{}", std::any::type_name::<T>())
}

fn main() {
    let mut rng = ark_std::test_rng();

    

    let set1 = vec![F::from(1), F::from(2), F::from(3), F::from(4)];
    let set2 = vec![F::from(3), F::from(4), F::from(5), F::from(6)];

    // the players need to agree on a generator for the group.
    // let's take the number 2 as the generator
    let generator = F::rand(&mut rng);
    let exponent = <F as PrimeField>::GENERATOR;

    print_type_of(&exponent);
    
    // step #1
    // a <-- KA.R
    // Player 1 samples a random value
    let a = F::rand(&mut rng);

    // step #2
    // m = KA.msg_1(a)
    let m = generator.pow(&exponent);
}