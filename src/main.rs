use ark_ff::{Field, PrimeField, BigInteger, BigInt};
// Now we'll use the prime field underlying the BLS12-381 G1 curve.
use ark_test_curves::bls12_381::Fq as F;
use ark_std::{One, Zero, UniformRand};

fn main() {
    let mut rng = ark_std::test_rng();

    // let set1_raw: [i32; 4] = [1, 2, 3, 4];
    // let set2_raw: [i32; 4] = [3, 4, 5, 6];

    let set1 = vec![F::from(1), F::from(2), F::from(3), F::from(4)];
    let set2 = vec![F::from(3), F::from(4), F::from(5), F::from(6)];

    // Player 1 samples a random value
    let alpha = F::rand(&mut rng);

    // Player 2 samples a random value
    let beta = F::rand(&mut rng);

    println!("{alpha}");
    println!("{beta}");

    // iter map collect was taken from https://doc.rust-lang.org/book/ch13-02-iterators.html

    // player 1 alpha-exponentiates
    let set1_alpha: Vec<_> = set1.iter().map(|x| alpha * x).collect();

    // player 2 beta
    let set1_alpha_beta: Vec<_> = set1_alpha.iter().map(|x| beta * x).collect();
    let set2_beta: Vec<_> = set2.iter().map(|x| beta * x).collect();

    // player 1 alpha
    let set2_beta_alpha: Vec<_> = set2_beta.iter().map(|x| alpha * x).collect();

    assert_eq!(set1_alpha_beta[3], set2_beta_alpha[1]);

    for x in &set1_alpha_beta {
        println!("{x}");
    }

    for x in &set2_beta_alpha {
        println!("{x}");
    }
}