use updns::exp3::*;
use rand::{rngs::StdRng, SeedableRng};

#[test]
fn exp3_test() {
    let mut seed = [0u8; 32];
    seed[0..9].copy_from_slice("exp3_test".as_bytes());
    let mut rng = StdRng::from_seed(seed);
    let mut exp3 = EXP3::new(2, 0.1, false);
    assert_eq!(exp3.probabilities(), [0.5, 0.5]);

    const N_ROUNDS: usize = 100;
    let mut total_actions: usize = 0;
    for _ in 0..N_ROUNDS {
        let action = exp3.take_action(&mut rng);
        exp3.give_reward(action, (1 - action) as f64);
        total_actions += action;
    }
    assert!(total_actions <= 20, "Action 0 should be strongly favored");

    exp3 = EXP3::new(2, 1.0, false);
    total_actions = 0;
    for _ in 0..N_ROUNDS {
        let action = exp3.take_action(&mut rng);
        exp3.give_reward(action, (1 - action) as f64);
        total_actions += action;
    }
    assert!(40 <= total_actions && total_actions <= 60, "No action should be strongly favored");
}