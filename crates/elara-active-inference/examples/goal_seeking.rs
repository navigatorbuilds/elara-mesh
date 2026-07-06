// Copyright (c) 2026 Elara Protocol contributors
// Licensed under MIT OR Apache-2.0

//! Active inference end to end in ~50 lines: a tiny POMDP where a free-energy
//! agent first *infers* where it is from a noisy observation, then *acts* to
//! fulfil a preference — minimizing expected free energy rather than maximizing
//! a hand-tuned reward.
//!
//! Run it:
//!
//! ```text
//! cargo run -p elara-active-inference --example goal_seeking
//! ```
//!
//! The world has two locations (A, B); the agent sees a noisy signal of where it
//! is and can move to either. Its only "goal" is a *preference* to observe B.
//! Perception (state belief) and action (policy) both fall out of one quantity —
//! free energy — which is the whole point of the free-energy principle.

use elara_active_inference::{Agent, GenerativeModel};

const AT_A: usize = 0;
const AT_B: usize = 1;
const SEE_A: usize = 0;
const SEE_B: usize = 1;
const GO_A: usize = 0;
const GO_B: usize = 1;

fn main() {
    // 2 states, 2 observations, 2 actions.
    let mut model = GenerativeModel::new(2, 2, 2);

    // A — likelihood P(obs | state): each location emits its own signal 90% of
    // the time (10% noise). This is what makes the observation *informative*.
    model.set_likelihood(SEE_A, AT_A, 0.9);
    model.set_likelihood(SEE_B, AT_A, 0.1);
    model.set_likelihood(SEE_A, AT_B, 0.1);
    model.set_likelihood(SEE_B, AT_B, 0.9);

    // B — transition P(next | current, action): moving is deterministic. "Go A"
    // lands at A from anywhere; "Go B" lands at B from anywhere.
    for cur in [AT_A, AT_B] {
        model.set_transition(GO_A, AT_A, cur, 1.0);
        model.set_transition(GO_B, AT_B, cur, 1.0);
    }

    // C — preference: the agent *wants* to observe B (log-preference 4.0).
    model.set_preference(SEE_B, 4.0);

    model.normalize_a();
    model.normalize_b();

    // The agent currently sees signal A. Step = infer state, then pick a policy.
    let mut agent = Agent::new(model);
    let r = agent.step(SEE_A);

    println!("observed SEE_A; agent belief over [at_A, at_B] = [{:.2}, {:.2}]",
        r.beliefs[AT_A], r.beliefs[AT_B]);
    println!("variational free energy: {:.3}", r.free_energy);
    println!("expected free energy per action [go_A, go_B] = [{:.3}, {:.3}]",
        r.expected_free_energy[GO_A], r.expected_free_energy[GO_B]);
    println!("chosen action: {}", if r.action == GO_B { "GO_B" } else { "GO_A" });

    // Robust, convention-independent checks: the posterior is a distribution,
    // and a SEE_A observation must make "at A" the more likely location.
    let belief_sum: f64 = r.beliefs.iter().sum();
    assert!((belief_sum - 1.0).abs() < 1e-9, "beliefs form a probability distribution");
    assert!(r.beliefs[AT_A] > r.beliefs[AT_B], "SEE_A implies the agent is probably at A");
    assert_eq!(r.expected_free_energy.len(), 2, "one EFE score per action");

    // Goal-directed behavior: observing B is preferred, so the policy that leads
    // there carries lower expected free energy, and the agent selects it.
    assert!(r.expected_free_energy[GO_B] < r.expected_free_energy[GO_A],
        "GO_B reaches the preferred observation, so it has lower expected free energy");
    assert_eq!(r.action, GO_B, "the agent acts to fulfil its preference (move toward B)");

    println!("\nPerception and action both emerged from minimizing free energy — no reward function.");
}
