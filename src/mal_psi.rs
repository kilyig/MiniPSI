/// This crate implements the malicious private set intersection (PSI) protocol described in
/// the paper by Rosulek and Trieu titled "Compact and Malicious Private Set Intersection for Small Sets."
/// An electronic copy of the paper can be found at https://eprint.iacr.org/2021/1159.pdf.
/// The protocol is described on Figure 4.
///
/// There are two parties, the sender and the receiver, and each of them have a set of integers (WLOG).
/// This PSI protocol reveals the intersection of these sets to the receiver.
/// 
/// The protocol starts by the sender running `sender_1` and sending the output to
/// the receiver. Then, the receiver uses the data it receives as input to `receiver_1`.
/// The outputted polynomial is sent back to the sender. The sender then runs
/// `sender_2` and sends the output to the receiver. Finally, the receiver runs `receiver_2`
/// with the output of `sender_2`. The output of `receiver_2` reveals the intersection
/// to the receiver.

use ark_ff::{
    fields::Field,
    BigInteger256, PrimeField, BigInt, MontBackend, MontConfig, Fp128, BigInteger, FftField
};

use ark_poly::{
    univariate::DensePolynomial,
    DenseUVPolynomial, Polynomial
};

use rand::seq::SliceRandom;
use rand::{thread_rng, Rng, rngs::ThreadRng};

use sha2::{Sha256, Digest};

use aes::Aes128;
use aes::cipher::{
    BlockEncrypt, BlockDecrypt, KeyInit, BlockSizeUser,
    generic_array::GenericArray,
};

use std::convert::TryInto;

#[derive(MontConfig)]
#[modulus = "340282366920938463463374607431768211297"] // 2^128 - 159 (largest prime that can be represented with 128 bits)
#[generator = "3"]
pub struct FqConfig;
pub type Fq = Fp128<MontBackend<FqConfig, 2>>;

// agreed by both parties
const AES_KEY: [u8; 16] = [185, 45, 74, 246, 159, 175, 5, 203, 150, 3, 209, 119, 141, 122, 116, 212];

/// Called by the sender to start the protocol.
/// Steps #1 and #2 in the paper.
/// 
/// # Outputs
///
/// * `a` - Random integer. Will be later used in `sender_2`
/// * `m` - KA message to be inputted to `receiver_1`
pub fn sender_1() -> (BigInteger256, Fq) {
    let mut rng: ThreadRng = thread_rng();

    // step #1
    // a <-- KA.R
    let a: BigInteger256 = rng.gen();

    // step #2
    // m = KA.msg_1(a)
    let m: Fq = Fq::GENERATOR.pow(a);

    (a, m)
}

/// Called by the receiver after receiving the output of `sender_1`.
/// Steps #3 and #4 in the paper.
/// 
/// # Arguments
///
/// * `m` - Field element received from the sender
/// * `set_y` - The receiver's private set
/// 
///  # Outputs
///
/// * `poly` - Polynomial ($P$ in the paper)
/// * `b_i_array` - Set of random values. To be later used in `receiver_2`
pub fn receiver_1(set_y: &Vec<u64>) -> (DensePolynomial::<Fq>, Vec<BigInt<4>>) {
    // step #3
    let mut rng: ThreadRng = thread_rng();
    let mut b_i_array: Vec<BigInt<4>> = Vec::new();
    let mut f_i_array: Vec<Fq> = Vec::new();
    // for i \in [n]:
    for _ in 0..set_y.len() {
        // b_i <-- KA.R
        let b_i: BigInteger256 = rng.gen();
        b_i_array.push(b_i);

        // m^'_i = KA.msg_2(b_1, m)
        let m_prime_i: Fq = Fq::GENERATOR.pow(b_i);

        // f_i = \Pi^{-1}(m^'_i)
        // let's cheat for now and assume that the ideal permutation is the identity function
        let f_i: Fq = pi_inverse(m_prime_i);

        f_i_array.push(f_i);
    }

    // P = interpol_F
    // first we need to hash the y_i values
    let mut y_hashes: Vec<Fq> = Vec::new();
    for i in 0..set_y.len() {
        let hash: Fq = hash_1(set_y[i]);
        y_hashes.push(hash);
    }

    let poly = interpolate(&y_hashes, &f_i_array);

    (poly, b_i_array)
}

/// Called by the sender after receiving the output of `receiver_1`.
/// Steps #5 and #6 in the paper.
/// 
/// # Arguments
///
/// * `a` - The randomness returned by `sender_1`
/// * `poly` - Polynomial outputted by `receiver_1`
/// * `set_x` - The sender's private set
/// 
/// # Outputs
///
/// * `capital_k` - Set of field elements ($K$ in the paper)
pub fn sender_2(a: BigInteger256, poly: DensePolynomial::<Fq>, set_x: &Vec<u64>) -> Vec<Fq> {    
    // TODO: abort if deg(P) < 1
    // step #5
    let mut capital_k: Vec<Fq> = Vec::new();
    // for i \in [n]:
    for i in 0..set_x.len() {
        let x_i: u64 = set_x[i];

        // first, hash x_i
        let hash: Fq = hash_1(x_i);

        // then, calculate the value of the polynomial at the hash value
        let poly_eval: Fq = poly.evaluate(&hash);

        // then, pass the output to the ideal permutation
        // let's cheat for now and assume that the ideal permutation is the identity function
        let permuted: Fq = pi(poly_eval);
        
        // then, calculate the KA key
        let k_i: Fq = permuted.pow(a);

        // finally, hash x_i and k_i
        let k_prime_i: Fq = hash_2(x_i, k_i);

        capital_k.push(k_prime_i);
    }

    // step #6
    // shuffle K
    // https://rust-random.github.io/rand/rand/seq/trait.SliceRandom.html#example-4
    let mut rng: ThreadRng = thread_rng();
    capital_k.shuffle(&mut rng);

    capital_k
}

/// Called by the receiver after receiving the output of `sender_2`.
/// Step #7 in the paper.
/// 
/// # Arguments
///
/// * `capital_k` - Set outputted by `sender_2`
/// * `m` - Field element received from the sender's first message (output of `sender_1`)
/// * `b_i_array` - Set of random field elements generated by `receiver_1`
/// * `set_y` - The receiver's private set
/// 
/// # Outputs
///
/// * `intersection` - The subset of the receiver's private set that only includes every element in the intersection
pub fn receiver_2(capital_k: Vec<Fq>, m: Fq, b_i_array: Vec<BigInt<4>>, set_y: &Vec<u64>) -> Vec<u64> {
    // step #7
    let mut intersection: Vec<u64> = Vec::new();
    for i in 0..set_y.len() {
        // KA.key_2(b_i, m)
        let key_2: Fq = m.pow(b_i_array[i]);

        let hash: Fq = hash_2(set_y[i], key_2);

        if capital_k.contains(&hash) {
            intersection.push(set_y[i]);
        }
    }

    intersection
}

/// Approximation for an ideal permutation.
/// Uses AES
/// $\Pi$ in the paper.
/// 
/// # Arguments
///
/// * `elt` - A field element
/// 
/// # Outputs
///
/// * `permuted` - A field element
fn pi(elt: Fq) -> Fq {
    let mut block = field_to_block(elt);

    let cipher = Aes128::new(&AES_KEY.into());
    cipher.encrypt_block(&mut block);

    let permuted = block_to_field(block);
    permuted
}

/// Inverse of the function `pi`.
/// Uses AES
/// $\Pi^{-1}$ in the paper.
/// 
/// # Arguments
///
/// * `elt` - A field element
/// 
/// # Outputs
///
/// * `permuted` - A field element
fn pi_inverse(elt: Fq) -> Fq {
    let mut block = field_to_block(elt);
    
    let cipher: Aes128 = Aes128::new(&AES_KEY.into());
    cipher.decrypt_block(&mut block);

    let permuted = block_to_field(block);

    permuted
}

/// Converts a field element into a block of 128 bits. This block later
/// gets inputted to AES.
///  
/// # Arguments
///
/// * `elt` - A field element
/// 
/// # Outputs
///
/// * `block` - An array with 16 bytes
fn field_to_block(elt: Fq) -> GenericArray<u8, <Aes128 as BlockSizeUser>::BlockSize> {
    let elt_bytes = elt.into_bigint().to_bytes_le();

    // TODO: this is ugly
    let block = GenericArray::from([
        elt_bytes[0],
        elt_bytes[1],
        elt_bytes[2],
        elt_bytes[3],
        elt_bytes[4],
        elt_bytes[5],
        elt_bytes[6],
        elt_bytes[7],
        elt_bytes[8],
        elt_bytes[9],
        elt_bytes[10],
        elt_bytes[11],
        elt_bytes[12],
        elt_bytes[13],
        elt_bytes[14],
        elt_bytes[15]
    ]);

    block
}

/// Converts a 128-bit block to a field element
///  
/// # Arguments
///
/// * `block` - An array with 16 bytes
/// 
/// # Outputs
///
/// * `elt` - A field element
fn block_to_field(block: GenericArray<u8, <Aes128 as BlockSizeUser>::BlockSize>) -> Fq {
    let elt: Fq = <Fq as PrimeField>::from_le_bytes_mod_order(block.as_slice());

    elt
}

/// Hash function from arbitrary string to field element
/// $H_1$ in the paper.
///
/// # Arguments
///
/// * `input` - An element of one of the private sets. In the future, the library may accept different element types, but currently only u64 is accepted.
/// 
/// # Outputs
/// 
/// * `hash` - A field element
fn hash_1(input: u64) -> Fq {
    // https://docs.rs/sha2/latest/sha2/
    let mut hasher = Sha256::new();
    hasher.update(input.to_le_bytes());
    let result = hasher.finalize();

    // map the output of the hash back to a field element
    let hash: Fq = <Fq as PrimeField>::from_le_bytes_mod_order(&result);

    hash
}

/// Hash function from arbitrary string x field element to field element
/// $H_2$ in the paper.
///
/// # Arguments
///
/// * `input1` - An element of one of the private sets. In the future, the library may accept different element types, but currently only u64 is accepted.
/// * `input2` - A field element
/// 
/// # Outputs
///
/// * `hash` - A field element
fn hash_2(input1: u64, input2: Fq) -> Fq {
    // finally, hash x_i with the output from the previous step
    let mut hasher = Sha256::new();
    hasher.update(input1.to_le_bytes());
    let k_i_string: String = std::format!("{input2}");
    hasher.update(k_i_string.as_bytes());
    let k_prime_i_bytes = hasher.finalize();

    let hash: Fq = <Fq as PrimeField>::from_le_bytes_mod_order(&k_prime_i_bytes);

    hash
}

/// given x coords construct Li polynomials
/// stolen from https://github.com/geometryresearch/fast-eval/blob/7fac903cce7ff5961c4fc8e5070c0544138adf15/src/subtree.rs
fn construct_lagrange_basis<F: FftField>(evaluation_domain: &[F]) -> Vec<DensePolynomial<F>> {
    let mut bases = Vec::with_capacity(evaluation_domain.len());
    for i in 0..evaluation_domain.len() {
        let mut l_i = DensePolynomial::from_coefficients_slice(&[F::one()]);
        let x_i = evaluation_domain[i];
        for (j, _) in evaluation_domain.iter().enumerate() {
            if j != i {
                let xi_minus_xj_inv = (x_i - evaluation_domain[j]).inverse().unwrap();
                l_i = l_i.naive_mul(
                    &DensePolynomial::from_coefficients_slice(&[
                        -evaluation_domain[j] * xi_minus_xj_inv,
                        xi_minus_xj_inv,
                    ]));
            }
        }

        bases.push(l_i);
    }

    bases
}

/// stolen from https://github.com/geometryresearch/fast-eval/blob/7fac903cce7ff5961c4fc8e5070c0544138adf15/src/subtree.rs
fn interpolate(roots: &Vec<Fq>, f_evals: &Vec<Fq>) -> DensePolynomial<Fq> {

    let lagrange_basis = construct_lagrange_basis(&roots);

    let mut f_slow = DensePolynomial::default();
    for (li, &fi) in lagrange_basis.iter().zip(f_evals.iter()) {
        f_slow += (fi, li);
    }

    f_slow
}

#[cfg(test)]
mod psi_unit_tests {
    use crate::mal_psi::{
        pi, pi_inverse, interpolate, Fq
    };

    use aes::{
        cipher::{
            generic_array::GenericArray, BlockEncrypt, BlockDecrypt
        },
        Aes128
    };
    use aes_gcm_siv::KeyInit;
    use ark_std::test_rng;
    use ark_ff::UniformRand;
    use ark_poly::Polynomial;

    #[test]
    fn test_field_bytes_conversion() {
        let key = GenericArray::from([0u8; 16]);
        let mut block = GenericArray::from([42u8; 16]);
        
        // Initialize cipher
        let cipher = Aes128::new(&key);
        
        let block_copy = block.clone();
        
        // Encrypt block in-place
        cipher.encrypt_block(&mut block);
        
        // And decrypt it back
        cipher.decrypt_block(&mut block);
        assert_eq!(block, block_copy);
    }

    #[test]
    fn test_ideal_permutation() {
        let mut rng = test_rng();
        for _ in 0..100 {
            let rand_elt: Fq = Fq::rand(&mut rng);
            assert_eq!(rand_elt, pi_inverse(pi(rand_elt)));
            assert_eq!(rand_elt, pi(pi_inverse(rand_elt)));
        }
    }

    #[test]
    fn test_interpolate() {
        let n: usize = 32;
        let mut rng = test_rng();

        let roots: Vec<Fq> = (0..n).map(|_| Fq::rand(&mut rng)).collect();    
        let f_evals: Vec<Fq> = (0..n).map(|_| Fq::rand(&mut rng)).collect();

        let poly = interpolate(&roots, &f_evals);

        for i in 0..roots.len() {
            assert_eq!(f_evals[i], poly.evaluate(&roots[i]));
        }
    }
}
