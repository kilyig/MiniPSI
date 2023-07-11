use mini_psi::psi::{sender_1, receiver_1, sender_2, receiver_2};

// private set of the sender
const SET_X: [u64; 3] = [1u64, 2u64, 3u64];

// private set of the receiver
const SET_Y: [u64; 3] = [3u64, 4u64, 5u64];

// changed the main() signature due to the AES implementation
// inspired by https://stackoverflow.com/questions/24245276/why-does-rust-not-have-a-return-value-in-the-main-function-and-how-to-return-a
// fn main() -> Result<(), aes_gcm_siv::Error> {

// }

#[test]
fn test_add() {
    let (a, m) = sender_1();

    /* the sender sends m to the receiver */
    
    let (poly, b_i_array) = receiver_1(m, SET_Y);

    /* the receiver sends poly to the receiver */

    let capital_k = sender_2(a, poly, SET_X);

    /* the sender sends K to the receiver */

    let output = receiver_2(capital_k, m, b_i_array, SET_Y);
    println!("{:?}", output);
}
