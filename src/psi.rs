use aes;
use aes::cipher::typenum::{UInt, UTerm, B0, B1};

use ark_ff::{
    fields::{Field, Fp64, MontBackend, MontConfig},
    BigInteger256, PrimeField, BigInt
};

use ark_poly::{
    univariate::DensePolynomial,
    DenseUVPolynomial, Polynomial
};

use rand::seq::SliceRandom;
use rand::{thread_rng, Rng, rngs::ThreadRng};

// https://docs.rs/sha2/latest/sha2/
use sha2::{Sha256, Digest};

use aes_gcm_siv::{
    aead::{Aead, KeyInit, OsRng},
    Aes128GcmSiv, Nonce // Or `Aes128GcmSiv`
};

// Defining your own field
// To demonstrate the various field operations, we can first define a prime ordered field $\mathbb{F}_{p}$ with $p = 17$. When defining a field $\mathbb{F}_p$, we need to provide the modulus(the $p$ in $\mathbb{F}_p$) and a generator. Recall that a generator $g \in \mathbb{F}_p$ is a field element whose powers comprise the entire field: $\mathbb{F}_p =\\{g, g^1, \ldots, g^{p-1}\\}$.
// We can then manually construct the field element associated with an integer with `Fp::from` and perform field addition, subtraction, multiplication, and inversion on it.
#[derive(MontConfig)]
#[modulus = "2305843009213693951"] // a Mersenne prime
#[generator = "3"]
pub struct FqConfig;
pub type Fq = Fp64<MontBackend<FqConfig, 1>>;

pub fn sender_1() -> (BigInteger256, Fq) {
    // generator for the group. agreed by both parties
    // TODO: generator should be a global variable
    let generator: Fq = Fq::from(3);

    // step #1
    // a <-- KA.R
    let a: BigInteger256 = BigInteger256::from(5586581436584319u64);

    // step #2
    // m = KA.msg_1(a)
    let m: Fq = generator.pow(a);

    (a, m)
}

pub fn receiver_1(m: Fq, set_y: &Vec<u64>) -> (DensePolynomial::<Fq>, Vec<BigInt<4>>) {
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
        let m_prime_i: Fq = m.pow(b_i);

        // f_i = \Pi^{-1}(m^'_i)
        let f_i: Fq = pi(m_prime_i);

        f_i_array.push(f_i);
    }

    // P = interpol_F
    // first we need to hash the y_i values
    let mut y_hashes: Vec<Fq> = Vec::new();
    for i in 0..set_y.len() {
        let hash: Fq = hash_1(set_y[i]);
        y_hashes.push(hash);
    }

    // now, create the polynomial. currently, the polynomial is in the evaluation 
    // form, but this form does render the protocol useless.

    // the following polynomial is random (so, a different poly than the one that needs to be sent by the receiver)
    // TODO: make sure that P is actually produced through interpolation
    let poly: DensePolynomial::<Fq> = DensePolynomial::<Fq>::rand(20 - 1, &mut rng);
    
    (poly, b_i_array)
}

pub fn sender_2(a: BigInteger256, poly: DensePolynomial::<Fq>, set_x: Vec<u64>) -> Vec<Fq> {
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

fn pi(input: Fq) -> Fq {
    // for the ideal permutation. because we need a simple fixed permutation, we don't need to change the key or nonce?
    // TODO: those looooooong types are ugly
    // TODO: these should be global variables
    let key: aes::cipher::generic_array::GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>> = Aes128GcmSiv::generate_key(&mut OsRng);
    let cipher: aes_gcm_siv::AesGcmSiv<aes::Aes128> = Aes128GcmSiv::new(&key);
    let nonce: &aes::cipher::generic_array::GenericArray<u8, aes::cipher::typenum::UInt<aes::cipher::typenum::UInt<aes::cipher::typenum::UInt<aes::cipher::typenum::UInt<aes::cipher::typenum::UTerm, aes::cipher::typenum::B1>, aes::cipher::typenum::B1>, aes::cipher::typenum::B0>, aes::cipher::typenum::B0>> = Nonce::from_slice(b"unique nonce"); // 96-bits; unique per message

    let input_string: String = std::format!("{input}");
    // In AES, encryption and decryption are done by the same operation
    // from: https://docs.rs/aes-gcm-siv/latest/aes_gcm_siv/#usage
    // also: https://stackoverflow.com/questions/23850486/how-do-i-convert-a-string-into-a-vector-of-bytes-in-rust
    // TODO: why does it give an error when I run `.decrypt`?
    // TODO: is is_ok() okay (lol) or should I propagate the error with Result<T, E>?
    let permuted_bytes = cipher.encrypt(nonce, input_string.as_bytes().as_ref());
    assert!(permuted_bytes.is_ok());
    let permuted: Fq = <Fq as PrimeField>::from_le_bytes_mod_order(&permuted_bytes.unwrap());

    permuted
}

// the input should be the same type (or have a similar interface whatever) as the elements in the input sets
fn hash_1(input: u64) -> Fq {
    // https://docs.rs/sha2/latest/sha2/
    let mut hasher = Sha256::new();
    hasher.update(input.to_le_bytes());
    let result = hasher.finalize();

    // need to shorten it to u64 for now.
    // represent those 8 bytes as a single u64
    let hash: Fq = <Fq as PrimeField>::from_le_bytes_mod_order(result[..].try_into().unwrap());

    hash
}

// input1 should be the same type (or have a similar interface whatever) as the elements in the input sets
// input2 should be a field element
fn hash_2(input1: u64, input2: Fq) -> Fq {
    // finally, hash x_i with the output from the previous step
    let mut hasher = Sha256::new();
    // TODO: when you stack up the `update`s, it doesn't overwrite everything except the last one, right?
    hasher.update(input1.to_le_bytes());
    let k_i_string: String = std::format!("{input2}");
    hasher.update(k_i_string.as_bytes());
    let k_prime_i_bytes = hasher.finalize();

    let hash: Fq = <Fq as PrimeField>::from_le_bytes_mod_order(k_prime_i_bytes[..].try_into().unwrap());

    hash
}

pub fn receiver_2(capital_k: Vec<Fq>, m: Fq, b_i_array: Vec<BigInt<4>>, set_y: &Vec<u64>) {
    // step #7
    let mut output: Vec<u64> = Vec::new();
    for i in 0..set_y.len() {
        // KA.key_2(b_i, m)
        let key_2: Fq = m.pow(b_i_array[i]);

        let hash: Fq = hash_2(set_y[i], key_2);

        if capital_k.contains(&hash) {
            output.push(set_y[i]);
        }
    }
}
