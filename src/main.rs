// Defining your own field
// To demonstrate the various field operations, we can first define a prime ordered field $\mathbb{F}_{p}$ with $p = 17$. When defining a field $\mathbb{F}_p$, we need to provide the modulus(the $p$ in $\mathbb{F}_p$) and a generator. Recall that a generator $g \in \mathbb{F}_p$ is a field element whose powers comprise the entire field: $\mathbb{F}_p =\\{g, g^1, \ldots, g^{p-1}\\}$.
// We can then manually construct the field element associated with an integer with `Fp::from` and perform field addition, subtraction, multiplication, and inversion on it.

use ark_ff::fields::{Field, Fp64, MontBackend, MontConfig};
use ark_ff::{BigInteger256, PrimeField};

use ark_poly::DenseUVPolynomial;
use ark_poly::univariate::DensePolynomial;

use rand::{thread_rng, Rng};

use ark_poly::Polynomial;

// https://docs.rs/sha2/latest/sha2/
use sha2::{Sha256, Digest};

use aes_gcm_siv::{
    aead::{Aead, KeyInit, OsRng},
    Aes128GcmSiv, Nonce // Or `Aes128GcmSiv`
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
    let a: BigInteger256 = BigInteger256::from(5586581436584319u64);

    // step #2
    // m = KA.msg_1(a)
    let m = g.pow(&a);

    /* the sender sends m to the receiver */
    
    // step #3
    let mut rng = thread_rng();
    let mut f_i_array: Vec<_> = Vec::new();
    let mut b_i_array: Vec<_> = Vec::new();
    // for i \in [n]:
    for i in 0..SET_Y.len() {
        // b_i <-- KA.R
        let b_i: BigInteger256 = rng.gen();
        b_i_array.push(b_i);
        println!("Random u64 value: {}", b_i);

        // m^'_i = KA.msg_2(b_1, m)
        let m_prime_i = m.pow(&b_i);

        // f_i = \Pi^{-1}(m^'_i)
        let m_prime_i_string: String = std::format!("{m_prime_i}");
        // In AES, encryption and decryption are done by the same operation
        // from: https://docs.rs/aes-gcm-siv/latest/aes_gcm_siv/#usage
        // also: https://stackoverflow.com/questions/23850486/how-do-i-convert-a-string-into-a-vector-of-bytes-in-rust
        let f_i_bytes = cipher.encrypt(nonce, m_prime_i_string.as_bytes().as_ref())?;
        let f_i =  <Fq as PrimeField>::from_le_bytes_mod_order(&f_i_bytes);
        f_i_array.push(f_i);
    }

    // P = interpol_F
    // first we need to hash the y_i values
    let mut y_hashes: Vec<_> = Vec::new();
    for i in 0..SET_Y.len() {
        // https://docs.rs/sha2/latest/sha2/
        let mut hasher = Sha256::new();
        hasher.update(SET_Y[i].to_le_bytes());
        let result = hasher.finalize();

        // need to shorten it to u64 for now.
        // represent those 8 bytes as a single u64
        let hash = <Fq as PrimeField>::from_le_bytes_mod_order(result[..].try_into().unwrap());

        y_hashes.push(hash);
    }

    println!("{:?}", y_hashes);
    println!("{:?}", f_i_array);

    // now, create the polynomial. currently, the polynomial is in the evaluation 
    // form, but this form might render the protocol useless.
    // TODO: find out if the evaluation form is okay.






    /* the receiver sends P to the receiver */





    // the following polynomial is a different poly than the one sent by the receiver
    // TODO: make sure that the sent P and the received P are the same

    // copied from https://github.com/arkworks-rs/sumcheck/blob/f4d971ee02a3116442bf393c305a734933b20dde/src/ml_sumcheck/protocol/verifier.rs#L298C13-L298C13
    // test a polynomial with 20 known points, i.e., with degree 19
    let poly = DensePolynomial::<Fq>::rand(20 - 1, &mut rng);
    let evals = (0..20)
        .map(|i| poly.evaluate(&Fq::from(i)))
        .collect::<Vec<Fq>>();

    // step #5
    let mut capital_k: Vec<_> = Vec::new();
    // for i \in [n]:
    for i in 0..SET_X.len() {
        // k_i = KA.key_1(a, \Pi(P(H_1(x_i))))
        let x_i = SET_X[i];

        // H_1(x_i)
        let mut hasher = Sha256::new();
        hasher.update(x_i.to_le_bytes());
        let result = hasher.finalize();
        let h_1_x_i = <Fq as PrimeField>::from_le_bytes_mod_order(result[..].try_into().unwrap());

        // P(H_1(x_i))
        let p_h_1_x_i = interpolate_uni_poly(&evals, h_1_x_i);

        // \Pi(P(H_1(x_i)))
        let p_h_1_x_i_string: String = std::format!("{p_h_1_x_i}");
        // In AES, encryption and decryption are done by the same operation
        // from: https://docs.rs/aes-gcm-siv/latest/aes_gcm_siv/#usage
        // also: https://stackoverflow.com/questions/23850486/how-do-i-convert-a-string-into-a-vector-of-bytes-in-rust
        // TODO: why does it give an error when I run `.decrypt`?
        let pi_p_h_1_x_i_bytes = cipher.encrypt(nonce, p_h_1_x_i_string.as_bytes().as_ref())?;
        let pi_p_h_1_x_i =  <Fq as PrimeField>::from_le_bytes_mod_order(&pi_p_h_1_x_i_bytes);
        
        let k_i = pi_p_h_1_x_i.pow(&a);

        let mut hasher2 = Sha256::new();
        // TODO: when you stack up the `update`s, it doesn't overwrite everything except the last one, right?
        hasher2.update(x_i.to_le_bytes());
        let k_i_string: String = std::format!("{k_i}");
        hasher2.update(k_i_string.as_bytes());
        let k_prime_i_bytes = hasher2.finalize();

        let k_prime_i = <Fq as PrimeField>::from_le_bytes_mod_order(k_prime_i_bytes[..].try_into().unwrap());


        capital_k.push(k_prime_i);
    }

    // step #6
    // TODO: shuffle K

    /* the sender sends K to the receiver */

    // step #7
    let mut output: Vec<u64> = Vec::new();
    for i in 0..SET_Y.len() {
        // KA.key_2(b_i, m)
        let key_2 = m.pow(&b_i_array[i]);

        let mut hasher2 = Sha256::new();
        // TODO: when you stack up the `update`s, it doesn't overwrite everything except the last one, right?
        hasher2.update(SET_Y[i].to_le_bytes());
        let key_2_string: String = std::format!("{key_2}");
        hasher2.update(key_2_string.as_bytes());
        let h_2_bytes = hasher2.finalize();

        let h_2 = <Fq as PrimeField>::from_le_bytes_mod_order(h_2_bytes[..].try_into().unwrap());

        if capital_k.contains(&h_2) {
            output.push(SET_Y[i]);
        }
    }

    println!("{:?}", output);

    Ok(())
}


// stolen from https://github.com/TheAlgorithms/Rust/blob/master/src/math/interpolation.rs
// [deleted]


// stolen from https://github.com/arkworks-rs/sumcheck/blob/f4d971ee02a3116442bf393c305a734933b20dde/src/ml_sumcheck/protocol/verifier.rs#L139
/// interpolate the *unique* univariate polynomial of degree *at most*
/// p_i.len()-1 passing through the y-values in p_i at x = 0,..., p_i.len()-1
/// and evaluate this  polynomial at `eval_at`. In other words, efficiently compute
///  \sum_{i=0}^{len p_i - 1} p_i[i] * (\prod_{j!=i} (eval_at - j)/(i-j))
fn interpolate_uni_poly<F: Field>(p_i: &[F], eval_at: F) -> F {
    let len = p_i.len();

    let mut evals = vec![];

    let mut prod = eval_at;
    evals.push(eval_at);

    //`prod = \prod_{j} (eval_at - j)`
    // we return early if 0 <= eval_at <  len, i.e. if the desired value has been passed
    let mut check = F::zero();
    for i in 1..len {
        if eval_at == check {
            return p_i[i - 1];
        }
        check += F::one();

        let tmp = eval_at - check;
        evals.push(tmp);
        prod *= tmp;
    }

    if eval_at == check {
        return p_i[len - 1];
    }

    let mut res = F::zero();
    // we want to compute \prod (j!=i) (i-j) for a given i
    //
    // we start from the last step, which is
    //  denom[len-1] = (len-1) * (len-2) *... * 2 * 1
    // the step before that is
    //  denom[len-2] = (len-2) * (len-3) * ... * 2 * 1 * -1
    // and the step before that is
    //  denom[len-3] = (len-3) * (len-4) * ... * 2 * 1 * -1 * -2
    //
    // i.e., for any i, the one before this will be derived from
    //  denom[i-1] = - denom[i] * (len-i) / i
    //
    // that is, we only need to store
    // - the last denom for i = len-1, and
    // - the ratio between the current step and the last step, which is the
    //   product of -(len-i) / i from all previous steps and we store
    //   this product as a fraction number to reduce field divisions.

    // We know
    //  - 2^61 < factorial(20) < 2^62
    //  - 2^122 < factorial(33) < 2^123
    // so we will be able to compute the ratio
    //  - for len <= 20 with i64
    //  - for len <= 33 with i128
    //  - for len >  33 with BigInt
    if p_i.len() <= 20 {
        let last_denom = F::from(u64_factorial(len - 1));
        let mut ratio_numerator = 1i64;
        let mut ratio_enumerator = 1u64;

        for i in (0..len).rev() {
            let ratio_numerator_f = if ratio_numerator < 0 {
                -F::from((-ratio_numerator) as u64)
            } else {
                F::from(ratio_numerator as u64)
            };

            res += p_i[i] * prod * F::from(ratio_enumerator)
                / (last_denom * ratio_numerator_f * evals[i]);

            // compute ratio for the next step which is current_ratio * -(len-i)/i
            if i != 0 {
                ratio_numerator *= -(len as i64 - i as i64);
                ratio_enumerator *= i as u64;
            }
        }
    } else if p_i.len() <= 33 {
        let last_denom = F::from(u128_factorial(len - 1));
        let mut ratio_numerator = 1i128;
        let mut ratio_enumerator = 1u128;

        for i in (0..len).rev() {
            let ratio_numerator_f = if ratio_numerator < 0 {
                -F::from((-ratio_numerator) as u128)
            } else {
                F::from(ratio_numerator as u128)
            };

            res += p_i[i] * prod * F::from(ratio_enumerator)
                / (last_denom * ratio_numerator_f * evals[i]);

            // compute ratio for the next step which is current_ratio * -(len-i)/i
            if i != 0 {
                ratio_numerator *= -(len as i128 - i as i128);
                ratio_enumerator *= i as u128;
            }
        }
    } else {
        // since we are using field operations, we can merge
        // `last_denom` and `ratio_numerator` into a single field element.
        let mut denom_up = field_factorial::<F>(len - 1);
        let mut denom_down = F::one();

        for i in (0..len).rev() {
            res += p_i[i] * prod * denom_down / (denom_up * evals[i]);

            // compute denom for the next step is -current_denom * (len-i)/i
            if i != 0 {
                denom_up *= -F::from((len - i) as u64);
                denom_down *= F::from(i as u64);
            }
        }
    }

    res
}

/// compute the factorial(a) = 1 * 2 * ... * a
#[inline]
fn u128_factorial(a: usize) -> u128 {
    let mut res = 1u128;
    for i in 1..=a {
        res *= i as u128;
    }
    res
}

/// compute the factorial(a) = 1 * 2 * ... * a
#[inline]
fn u64_factorial(a: usize) -> u64 {
    let mut res = 1u64;
    for i in 1..=a {
        res *= i as u64;
    }
    res
}

/// compute the factorial(a) = 1 * 2 * ... * a
#[inline]
fn field_factorial<F: Field>(a: usize) -> F {
    let mut res = F::one();
    for i in 1..=a {
        res *= F::from(i as u64);
    }
    res
}
