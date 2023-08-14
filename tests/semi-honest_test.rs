use mini_psi::sem_hon_psi::{sender_1, receiver_1, receiver_2};

// changed the main() signature due to the AES implementation
// inspired by https://stackoverflow.com/questions/24245276/why-does-rust-not-have-a-return-value-in-the-main-function-and-how-to-return-a

#[test]
fn test_dh_two_small_sets() {
    // TODO: allow the sets to contain anything that is hashable

    // private set of the sender
    let set_x: Vec<u64> = [1u64, 2u64, 3u64].to_vec();

    // private set of the receiver
    let set_y: Vec<u64> = [3u64, 4u64, 5u64].to_vec();

    /* the receiver starts the protocol */

    let (set_y_alpha, alpha) = receiver_1(&set_y);

    /* the receiver sends set_y_alpha to the sender */
    
    let (set_y_alpha_beta, set_x_beta) = sender_1(&set_y_alpha, &set_x);

    /* the sender sends set_y_alpha_beta and set_x_beta to the receiver */

    let intersection = receiver_2(&set_y, alpha, &set_y_alpha_beta, &set_x_beta);

    println!("{:?}", intersection);
}
