use rand::distributions::WeightedIndex;
use rand::prelude::*;
use rand::rngs::StdRng;

#[derive(Debug, Clone)]
pub struct EXP3Round {
    pub weights: Vec<f64>,
    pub probabilities: Vec<f64>,
    pub action: usize,
    pub reward: f64,
}

#[derive(Debug, Clone)]
pub struct EXP3 {
    pub no_actions: usize,
    pub weights: Vec<f64>,
    pub max_weight: f64,
    pub gamma: f64,
    pub round: u64,
    waiting_reward: bool,
    enable_history: bool,
    enforce_strict_order: bool,
    pub history: Vec<EXP3Round>,
}

/// An EXP3 instance
impl EXP3 {
    pub fn new(
        no_actions: usize,
        gamma: f64,
        enable_history: bool,
        enforce_strict_order: bool,
    ) -> EXP3 {
        EXP3 {
            no_actions,
            weights: vec![1.0; no_actions],
            max_weight: 100.0,
            gamma,
            round: 0,
            waiting_reward: false,
            enable_history,
            enforce_strict_order,
            history: Vec::new(),
        }
    }

    /// Returns the current probabilities for each actions.
    pub fn probabilities(&self) -> Vec<f64> {
        let weights_sum: f64 = self.weights.iter().sum();
        self.weights
            .iter()
            .map(|w| {
                ((1.0 - self.gamma) * (w / weights_sum)) + (self.gamma / self.no_actions as f64)
            })
            .collect()
    }

    /// Returns the action that should be taken.
    pub fn take_action(&mut self, rng: &mut StdRng) -> usize {
        assert!(
            !self.enforce_strict_order || !self.waiting_reward,
            "EXP3 has not received a reward yet"
        );
        let dist = WeightedIndex::new(&self.probabilities()).unwrap();
        let action = dist.sample(rng);
        self.waiting_reward = true;
        return action;
    }

    /// Gives the reward corresponding to the action taken.
    pub fn give_reward(&mut self, action: usize, reward: f64) {
        assert!(action < self.no_actions, "Action {action} is unknown");
        assert!(
            0.0 <= reward && reward <= 1.0,
            "Reward {reward} is not comprised in [0, 1]"
        );
        assert!(
            !self.enforce_strict_order || self.waiting_reward,
            "EXP3 has not taken an action yet"
        );

        let estimated_reward = reward / self.probabilities()[action];
        self.weights[action] *= f64::exp(estimated_reward * self.gamma / (self.no_actions as f64));
        let weights_sum: f64 = self.weights.iter().sum();
        for w in self.weights.iter_mut() {
            *w *= self.max_weight / weights_sum;
            *w = f64::max(1.0, *w)
        }

        self.round += 1;
        self.waiting_reward = false;
        self.history.push(EXP3Round {
            weights: self.weights.clone(),
            probabilities: self.probabilities(),
            action,
            reward,
        });
    }
}
