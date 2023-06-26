// Defining your own field
// To demonstrate the various field operations, we can first define a prime ordered field $\mathbb{F}_{p}$ with $p = 17$. When defining a field $\mathbb{F}_p$, we need to provide the modulus(the $p$ in $\mathbb{F}_p$) and a generator. Recall that a generator $g \in \mathbb{F}_p$ is a field element whose powers comprise the entire field: $\mathbb{F}_p =\\{g, g^1, \ldots, g^{p-1}\\}$.
// We can then manually construct the field element associated with an integer with `Fp::from` and perform field addition, subtraction, multiplication, and inversion on it.

use ark_ff::fields::{Field, Fp64, MontBackend, MontConfig};
use ark_ff::{BigInteger64};

use rand::{thread_rng, Rng};

use aes_gcm_siv::Aes256GcmSiv;

#[derive(MontConfig)]
#[modulus = "2305843009213693951"] // a Mersenne prime
#[generator = "3"]
pub struct FqConfig;
pub type Fq = Fp64<MontBackend<FqConfig, 1>>;

fn main() {
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
        
    }

    println!("{}", m);
}