# elara-active-inference

A small, dependency-free **active inference** agent in Rust. The agent holds a
generative model of a discrete POMDP and, on each observation, performs
variational state inference and selects the action that minimizes *expected*
free energy. Need, curiosity, and goal-seeking are not hand-coded — they fall
out of the math.

Extracted as a standalone crate from the [Elara Protocol](https://github.com/navigatorbuilds/elara-mesh),
where it drives the node's cognitive layer. Pure `std`, **zero dependencies**.

## The generative model

Four matrices, in the usual active-inference notation:

- **A** — observation likelihood `P(o | s)` (`set_likelihood`, `normalize_a`)
- **B** — transition dynamics `P(s' | s, a)` (`set_transition`, `normalize_b`)
- **C** — preferences: a log-prior over *observations* the agent expects to
  encounter. **This is "Need"** — not a reward function. The agent acts to make
  its predictions come true; when reality diverges, free energy rises and it is
  driven to act (`set_preference`).
- **D** — prior over the initial hidden state `P(s_0)`.

`Agent::step(observation)` returns an `InferenceResult` with the posterior
`beliefs` over states, the scalar `free_energy`, the `expected_free_energy` per
policy, the selected `action`, the `policy_distribution`, and the
`prediction_error`. Call `enable_learning()` to let the agent update A/B/D from
experience.

## Example

```rust
use elara_active_inference::{Agent, GenerativeModel};

// A tiny POMDP: 3 hidden states, 3 observations, 2 actions.
let mut model = GenerativeModel::new(3, 3, 2);

// C — preferences ("Need"): the agent prefers to observe outcome 2.
model.set_preference(2, 4.0);

// (Populate A/B with set_likelihood / set_transition for a real model, then:)
model.normalize_a();
model.normalize_b();

let mut agent = Agent::new(model);
let result = agent.step(/* observation = */ 0);
println!(
    "free energy {:.3}, chose action {}",
    result.free_energy, result.action
);
```

## License

Licensed under either of [MIT](LICENSE-MIT) or
[Apache-2.0](LICENSE-APACHE) at your option. (The Elara node itself is
AGPL-3.0; this extracted library is permissively licensed for reuse.)
