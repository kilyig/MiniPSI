use std::collections::HashSet;

use mini_psi::psi::{sender_1, receiver_1, sender_2, receiver_2};

// changed the main() signature due to the AES implementation
// inspired by https://stackoverflow.com/questions/24245276/why-does-rust-not-have-a-return-value-in-the-main-function-and-how-to-return-a

#[test]
fn test_two_small_sets() {
    // private set of the sender
    let set_x: Vec<u64> = [1u64, 2u64, 3u64].to_vec();

    // private set of the receiver
    let set_y: Vec<u64> = [3u64, 4u64, 5u64].to_vec();

    run_protocol_and_check(&set_x, &set_y);
}

#[test]
fn test_fuzzing() {
    // private set of the sender
    let set_x: Vec<u64> = [1u64, 4u64, 3u64].to_vec();

    // private set of the receiver
    let set_y: Vec<u64> = [3u64, 4u64, 5u64].to_vec();

    run_protocol_and_check(&set_x, &set_y);
}

fn run_protocol_and_check(set_x: &Vec<u64>, set_y: &Vec<u64>) {
    let plaintext_intersection: HashSet<u64> = plaintext_intersection(&set_x, &set_y).into_iter().collect();
    let protocol_intersection: HashSet<u64> = protocol_intersection(&set_x, &set_y).into_iter().collect();

    assert!(plaintext_intersection == protocol_intersection);

}

fn plaintext_intersection(set_x: &Vec<u64>, set_y: &Vec<u64>) -> Vec<u64> {
    let mut intersection: Vec<u64> = Vec::new();
    for i in 0..set_x.len() {
        if set_y.contains(&set_x[i]) {
            intersection.push(set_x[i]);
        }
    }

    intersection
}

fn protocol_intersection(set_x: &Vec<u64>, set_y: &Vec<u64>) -> Vec<u64> {
    let (a, m) = sender_1();

    /* the sender sends m to the receiver */
    
    let (poly, b_i_array) = receiver_1(&set_y);

    /* the receiver sends poly to the receiver */

    let capital_k = sender_2(a, poly, &set_x);

    /* the sender sends K to the receiver */

    let intersection = receiver_2(capital_k, m, b_i_array, &set_y);

    intersection
}