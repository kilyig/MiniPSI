use mini_psi::psi::{sender_1, receiver_1, sender_2, receiver_2};

// changed the main() signature due to the AES implementation
// inspired by https://stackoverflow.com/questions/24245276/why-does-rust-not-have-a-return-value-in-the-main-function-and-how-to-return-a

#[test]
fn test_two_small_sets() {
    // private set of the sender
    let set_x: Vec<u64> = [1u64, 4u64, 3u64].to_vec();

    // private set of the receiver
    let set_y: Vec<u64> = [3u64, 4u64, 5u64].to_vec();

    // let plaintext_intersection = plaintext_intersection(&set_x, &set_y);
    let protocol_intersection = protocol_intersection(&set_x, &set_y);

    println!("{:?}", protocol_intersection);
}

// fn plaintext_intersection(set_x: &Vec<u64>, set_y: &Vec<u64>) {
//     let intersection: Vec<u64> = set_x.into_iter().filter(|item| set_y.contains(item)).collect();
// }

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