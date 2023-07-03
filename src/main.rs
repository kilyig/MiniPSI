// Defining your own field
// To demonstrate the various field operations, we can first define a prime ordered field $\mathbb{F}_{p}$ with $p = 17$. When defining a field $\mathbb{F}_p$, we need to provide the modulus(the $p$ in $\mathbb{F}_p$) and a generator. Recall that a generator $g \in \mathbb{F}_p$ is a field element whose powers comprise the entire field: $\mathbb{F}_p =\\{g, g^1, \ldots, g^{p-1}\\}$.
// We can then manually construct the field element associated with an integer with `Fp::from` and perform field addition, subtraction, multiplication, and inversion on it.

use ark_ff::fields::{Field, Fp64, MontBackend, MontConfig};
use ark_ff::{BigInteger64};

use rand::{thread_rng, Rng};

use std::io;

// https://docs.rs/sha2/latest/sha2/
use sha2::{Sha256, Digest};

use aes_gcm_siv::{
    aead::{Aead, KeyInit, OsRng},
    Aes128GcmSiv, Nonce, Error // Or `Aes128GcmSiv`
};

#[derive(MontConfig)]
#[modulus = "2305843009213693951"] // a Mersenne prime
#[generator = "3"]
pub struct FqConfig;
pub type Fq = Fp64<MontBackend<FqConfig, 1>>;

// changed the main() signature due to the AES implementation
// inspired by https://stackoverflow.com/questions/24245276/why-does-rust-not-have-a-return-value-in-the-main-function-and-how-to-return-a
fn main() -> Result<(), aes_gcm_siv::Error> {

    // for the ideal permutation. because we need a simple fixed permutation, we don't need to change the key or nonce?
    let key = Aes128GcmSiv::generate_key(&mut OsRng);
    let cipher = Aes128GcmSiv::new(&key);
    let nonce = Nonce::from_slice(b"unique nonce"); // 96-bits; unique per message

    // private set of the sender
    const SET_X: [u64; 3] = [1u64, 2u64, 3u64];

    // private set of the receiver
    const SET_Y: [u64; 3] = [3u64, 4u64, 5u64];

    // generator for the group. agreed by both parties
    let g = Fq::from(3);

    // step #1
    // a <-- KA.R
    let a: BigInteger64 = BigInteger64::from(5586581436584319u64);

    // step #2
    // m = KA.msg_1(a)
    let m = g.pow(&a);

    /* the sender sends m to the receiver */
    
    // step #3
    let mut rng = thread_rng();
    // for i \in [n]:
    for i in 0..SET_Y.len() {
        // b_i <-- KA.R
        let random_u64: u64 = rng.gen();
        let b_i: BigInteger64 = BigInteger64::from(random_u64);
        println!("Random u64 value: {}", b_i);

        // m^'_i = KA.msg_2(b_1, m)
        let m_prime_i = m.pow(&b_i);

        // f_i = \Pi^{-1}(m^'_i)
        let m_prime_i_string: String = std::format!("{m_prime_i}");
        // In AES, encryption and decryption are done by the same operation
        // from: https://docs.rs/aes-gcm-siv/latest/aes_gcm_siv/#usage
        // also: https://stackoverflow.com/questions/23850486/how-do-i-convert-a-string-into-a-vector-of-bytes-in-rust
        let f_i_bytes = cipher.encrypt(nonce, m_prime_i_string.as_bytes().as_ref())?;

        println!("mem: {:?}", std::mem::size_of_val(&m_prime_i_string));
        println!("m_prime_i_string: {:?}", m_prime_i_string);
        println!("f_i: {:?}", f_i_bytes);
        println!("f_i length: {}", f_i_bytes.len());
        
        // // the two lines below work
        // let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())?;
        // assert_eq!(&plaintext, m_prime_i_string.as_bytes());
    }

    // P = interpol_F
    println!("test {:?}", b"Hello");

    // first we need to hash the y_i values
    let mut y_hashes: [u64; SET_Y.len()] = [0u64; SET_Y.len()];
    for i in 0..SET_Y.len() {
        let mut hasher = Sha256::new();
        hasher.update(SET_Y[i].to_ne_bytes());
        let result = hasher.finalize();
        // println!(" result {i}: {:?}", result);
        // println!(" length {:?}", result.len());

        // need to shorten in to u64 for now.
        // represent those 8 bytes as a single u64
        let finala: u64 = u64::from_ne_bytes(result[..8].try_into().unwrap());

        // println!("{}", finala);

        y_hashes[i] = finala;
    }

    println!("{:?}", y_hashes);
    

    Ok(())
}


// stolen from https://github.com/TheAlgorithms/Rust/blob/master/src/math/interpolation.rs
pub fn lagrange_polynomial_interpolation(x: f64, defined_points: &Vec<(f64, f64)>) -> f64 {
    let mut defined_x_values: Vec<f64> = Vec::new();
    let mut defined_y_values: Vec<f64> = Vec::new();

    for (x, y) in defined_points {
        defined_x_values.push(*x);
        defined_y_values.push(*y);
    }

    let mut sum = 0.0;

    for y_index in 0..defined_y_values.len() {
        let mut numerator = 1.0;
        let mut denominator = 1.0;
        for x_index in 0..defined_x_values.len() {
            if y_index == x_index {
                continue;
            }
            denominator *= defined_x_values[y_index] - defined_x_values[x_index];
            numerator *= x - defined_x_values[x_index];
        }

        sum += numerator / denominator * defined_y_values[y_index];
    }
    sum
}