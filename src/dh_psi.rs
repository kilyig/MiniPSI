use ark_ff::{
    fields::{Field, Fp64, MontBackend, MontConfig},
    BigInteger256, PrimeField
};

use rand::{thread_rng, Rng, rngs::ThreadRng};

// https://docs.rs/sha2/latest/sha2/
use sha2::{Sha256, Digest};

// Defining your own field
// To demonstrate the various field operations, we can first define a prime ordered field $\mathbb{F}_{p}$ with $p = 17$. When defining a field $\mathbb{F}_p$, we need to provide the modulus(the $p$ in $\mathbb{F}_p$) and a generator. Recall that a generator $g \in \mathbb{F}_p$ is a field element whose powers comprise the entire field: $\mathbb{F}_p =\\{g, g^1, \ldots, g^{p-1}\\}$.
// We can then manually construct the field element associated with an integer with `Fp::from` and perform field addition, subtraction, multiplication, and inversion on it.
#[derive(MontConfig)]
#[modulus = "2305843009213693951"] // a Mersenne prime
#[generator = "3"]
pub struct FqConfig;
pub type Fq = Fp64<MontBackend<FqConfig, 1>>;


pub fn receiver_1(set_y: &Vec<u64>) -> (Vec<Fq>, BigInteger256) {
    let mut rng: ThreadRng = thread_rng();

    // receiver's randomness
    let alpha: BigInteger256 = rng.gen();

    // TODO: map + collect
    // relevant link: https://users.rust-lang.org/t/how-can-i-pass-a-function-with-arguments-in-map/43221/2
    // need a bit more than simple map because alpha needs to be passed in as a parameter
    let mut set_y_alpha: Vec<Fq> = Vec::new();
    for elt in set_y {
        let mapped_to_field_elt = hash(elt);
        let exponentiated: Fq = mapped_to_field_elt.pow(alpha);
        set_y_alpha.push(exponentiated);
    }

    (set_y_alpha, alpha)
}

pub fn sender_1(set_y_alpha: &Vec<Fq>, set_x: &Vec<u64>) -> (Vec<Fq>, Vec<Fq>) {
    let mut rng: ThreadRng = thread_rng();

    // sender's randomness
    let beta: BigInteger256 = rng.gen();

    let mut set_y_alpha_beta: Vec<Fq> = Vec::new();
    for elt in set_y_alpha {
        let exponentiated: Fq = elt.pow(beta);
        set_y_alpha_beta.push(exponentiated);
    }

    let mut set_x_beta: Vec<Fq> = Vec::new();
    for elt in set_x {
        let mapped_to_field_elt = hash(elt);
        let exponentiated: Fq = mapped_to_field_elt.pow(beta);
        set_x_beta.push(exponentiated);
    }

    (set_y_alpha_beta, set_x_beta)
}

pub fn receiver_2(set_y: &Vec<u64>, alpha: BigInteger256, set_y_alpha_beta: &Vec<Fq>, set_x_beta: &Vec<Fq>) -> Vec<u64> {

    let mut set_x_beta_alpha: Vec<Fq> = Vec::new();
    for elt in set_x_beta {
        let exponentiated: Fq = elt.pow(alpha);
        set_x_beta_alpha.push(exponentiated);
    }

    println!("{:?}", set_y_alpha_beta);
    println!("{:?}", set_x_beta_alpha);


    let mut intersection: Vec<u64> = Vec::new();
    for (i, elt_y) in set_y_alpha_beta.iter().enumerate() {
        for elt_x in set_x_beta_alpha.iter() {
            if elt_y == elt_x {
                intersection.push(set_y[i]);
            }
        }
    }

    intersection
}


fn hash(input: &u64) -> Fq {
    // https://docs.rs/sha2/latest/sha2/
    let mut hasher = Sha256::new();
    hasher.update(input.to_le_bytes());
    let result = hasher.finalize();

    // need to shorten it to u64 for now.
    // represent those 8 bytes as a single u64
    let hash: Fq = <Fq as PrimeField>::from_le_bytes_mod_order(&result);

    hash
}
