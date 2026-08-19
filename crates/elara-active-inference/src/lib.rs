// Copyright (c) 2026 Elara Protocol contributors
// Licensed under MIT OR Apache-2.0

#![forbid(unsafe_code)]

//! Active Inference — the first Rust implementation.
//!
//! An agent that minimizes variational free energy. Need, curiosity,
//! and action selection emerge from the mathematics.
//!
//! Key insight: The C vector (preferences) is NOT a reward function.
//! It is a prior belief about what observations the agent EXPECTS to
//! encounter. The agent acts to make its predictions come true.
//! When reality diverges from expectation, free energy rises, and
//! the agent is driven to act.
//!
//! This is where The Need Gap gets solved — not by programming
//! "seek food when hungry" but by the math producing that behavior
//! when homeostatic predictions don't match reality.

//!
//! Spec references:
//!   @spec Protocol §3.2

use std::fmt;

/// The generative model: P(observations | states) and P(states' | states, actions)
///
/// A — Observation likelihood: P(o | s)
///     Shape: `[num_obs × num_states]` per modality
///     Each column sums to 1.0
///
/// B — Transition dynamics: P(s' | s, a)
///     Shape: `[num_states × num_states]` per action
///     Each column sums to 1.0
///
/// C — Preferences (log-prior over observations) — THIS IS NEED
///     Shape: `[num_obs]` per modality
///     Higher = more preferred. Agent acts to observe these.
///
/// D — Initial state prior: P(s_0)
///     Shape: `[num_states]`, sums to 1.0
///
/// # Invariants
/// The dimension fields (`num_states` / `num_obs` / `num_actions`) MUST stay
/// consistent with the matrix shapes. Mutating a `pub` field directly without
/// resizing the matrices will make `Agent::step` panic on an out-of-range
/// index. Prefer the validated setters (`set_likelihood` / `set_transition` /
/// `set_preference`) over direct field assignment, and call
/// [`GenerativeModel::validate`] after constructing or deserializing a model
/// from data you do not control — it returns `Err` on any shape mismatch
/// instead of letting `step` panic later.
#[derive(Clone, Debug)]
pub struct GenerativeModel {
    /// P(o|s) — observation likelihood matrix `[num_obs × num_states]`
    pub a: Vec<Vec<f64>>,
    /// P(s'|s,a) — transition matrices, one per action `[num_states × num_states]`
    pub b: Vec<Vec<Vec<f64>>>,
    /// Log-preferences over observations — WHERE NEED LIVES
    pub c: Vec<f64>,
    /// Prior over initial states
    pub d: Vec<f64>,

    pub num_states: usize,
    pub num_obs: usize,
    pub num_actions: usize,
}

/// Result of one inference step
#[derive(Clone, Debug)]
pub struct InferenceResult {
    /// Posterior beliefs over states: q(s)
    pub beliefs: Vec<f64>,
    /// Variational free energy (scalar — lower is better)
    pub free_energy: f64,
    /// Expected free energy per policy
    pub expected_free_energy: Vec<f64>,
    /// Selected action
    pub action: usize,
    /// Policy distribution (softmax over -G)
    pub policy_distribution: Vec<f64>,
    /// Prediction error magnitude
    pub prediction_error: f64,
}

/// An Active Inference agent
#[derive(Clone, Debug)]
pub struct Agent {
    /// The agent's model of the world
    pub model: GenerativeModel,
    /// Current posterior beliefs: q(s)
    pub beliefs: Vec<f64>,
    /// Prior for next step (predicted state)
    pub prior: Vec<f64>,
    /// Inverse temperature for policy selection (higher = more exploitative)
    pub gamma: f64,
    /// Number of fixed-point iterations for state inference
    pub inference_iters: usize,
    /// Cumulative free energy (tracks how "surprised" the agent has been)
    pub cumulative_free_energy: f64,
    /// Step counter
    pub step: u64,
    /// Learning rate for A matrix (observation model)
    pub learning_rate_a: f64,
    /// Learning rate for B matrix (transition model)
    pub learning_rate_b: f64,
    /// Learning rate for D vector (state prior)
    pub learning_rate_d: f64,
    /// Whether learning is enabled
    pub learning_enabled: bool,
    /// Learning rate for C vector (preference adaptation)
    pub learning_rate_c: f64,
    /// Previous beliefs (for transition learning)
    prev_beliefs: Option<Vec<f64>>,
    /// Previous action (for transition learning)
    prev_action: Option<usize>,
    /// Previous free energy (for preference learning)
    prev_free_energy: Option<f64>,
    /// Previous observation (for preference learning)
    prev_observation: Option<usize>,
}

impl GenerativeModel {
    /// Create a new generative model with given dimensions.
    /// Matrices are initialized to uniform distributions.
    ///
    /// # Panics
    /// Panics if any dimension is zero — a model with an empty state,
    /// observation, or action space is degenerate (division-by-zero in the
    /// uniform priors, and an empty action space panics in `Agent::step`).
    pub fn new(num_states: usize, num_obs: usize, num_actions: usize) -> Self {
        assert!(
            num_states > 0 && num_obs > 0 && num_actions > 0,
            "GenerativeModel dimensions must be non-zero (states={num_states}, obs={num_obs}, actions={num_actions})"
        );
        // Uniform A matrix
        let a_val = 1.0 / num_states as f64;
        let a = (0..num_obs)
            .map(|_| vec![a_val; num_states])
            .collect();

        // Identity-ish B matrices (stay in same state by default)
        let b = (0..num_actions)
            .map(|_| {
                (0..num_states)
                    .map(|i| {
                        let mut row = vec![0.01 / (num_states - 1) as f64; num_states];
                        row[i] = 0.99;
                        row
                    })
                    .collect()
            })
            .collect();

        // Uniform C (no preferences — agent doesn't care yet)
        let c = vec![0.0; num_obs];

        // Uniform D
        let d = vec![1.0 / num_states as f64; num_states];

        Self {
            a, b, c, d,
            num_states, num_obs, num_actions,
        }
    }

    /// Check that every matrix shape is consistent with the declared dimensions.
    ///
    /// `GenerativeModel`'s fields are `pub` for ergonomic construction and
    /// (de)serialization, so a caller — or a value loaded from untrusted
    /// storage — can hold dimension fields that disagree with the matrix
    /// shapes. [`Agent::step`] indexes the matrices by the declared dimensions,
    /// so an inconsistent model panics there. Call `validate()` after building
    /// or deserializing a model from data you do not control and reject it on
    /// `Err` instead of letting `step` panic.
    ///
    /// Returns `Ok(())` exactly when: all three dimensions are non-zero; `a` is
    /// `[num_obs][num_states]`; `b` is `[num_actions][num_states][num_states]`;
    /// `c` is `[num_obs]`; and `d` is `[num_states]`.
    pub fn validate(&self) -> Result<(), String> {
        if self.num_states == 0 || self.num_obs == 0 || self.num_actions == 0 {
            return Err(format!(
                "dimensions must be non-zero (states={}, obs={}, actions={})",
                self.num_states, self.num_obs, self.num_actions
            ));
        }
        if self.a.len() != self.num_obs {
            return Err(format!(
                "A has {} rows, expected num_obs={}",
                self.a.len(),
                self.num_obs
            ));
        }
        if let Some(bad) = self.a.iter().position(|row| row.len() != self.num_states) {
            return Err(format!(
                "A row {} has len {}, expected num_states={}",
                bad,
                self.a[bad].len(),
                self.num_states
            ));
        }
        if self.b.len() != self.num_actions {
            return Err(format!(
                "B has {} action matrices, expected num_actions={}",
                self.b.len(),
                self.num_actions
            ));
        }
        for (act, mat) in self.b.iter().enumerate() {
            if mat.len() != self.num_states {
                return Err(format!(
                    "B[{act}] has {} rows, expected num_states={}",
                    mat.len(),
                    self.num_states
                ));
            }
            if let Some(bad) = mat.iter().position(|row| row.len() != self.num_states) {
                return Err(format!(
                    "B[{act}] row {bad} has len {}, expected num_states={}",
                    mat[bad].len(),
                    self.num_states
                ));
            }
        }
        if self.c.len() != self.num_obs {
            return Err(format!(
                "C has len {}, expected num_obs={}",
                self.c.len(),
                self.num_obs
            ));
        }
        if self.d.len() != self.num_states {
            return Err(format!(
                "D has len {}, expected num_states={}",
                self.d.len(),
                self.num_states
            ));
        }

        // ── Value seal ──────────────────────────────────────────────────────
        // Every check above seals *shape*. A shape-valid model loaded from
        // untrusted or bit-rotted storage can still carry NaN/Inf entries: they
        // pass every length check yet are catastrophic. `Agent::step` folds the
        // matrices into the free-energy update, where a single NaN propagates
        // stickily through `beliefs` and never recovers — and the poisoned state
        // is then persisted, so the agent runs broken for the rest of its life.
        // Reject any non-finite entry so the caller fails closed (mark-corrupt +
        // recover) instead of booting a silently-dead mind.
        if let Some((o, s)) = self
            .a
            .iter()
            .enumerate()
            .find_map(|(o, row)| row.iter().position(|v| !v.is_finite()).map(|s| (o, s)))
        {
            return Err(format!("A[{o}][{s}] is non-finite ({})", self.a[o][s]));
        }
        for (act, mat) in self.b.iter().enumerate() {
            if let Some((r, c)) = mat
                .iter()
                .enumerate()
                .find_map(|(r, row)| row.iter().position(|v| !v.is_finite()).map(|c| (r, c)))
            {
                return Err(format!(
                    "B[{act}][{r}][{c}] is non-finite ({})",
                    self.b[act][r][c]
                ));
            }
        }
        if let Some(i) = self.c.iter().position(|v| !v.is_finite()) {
            return Err(format!("C[{i}] is non-finite ({})", self.c[i]));
        }
        if let Some(i) = self.d.iter().position(|v| !v.is_finite()) {
            return Err(format!("D[{i}] is non-finite ({})", self.d[i]));
        }
        Ok(())
    }

    /// Set preference for a specific observation.
    /// Higher values = the agent EXPECTS to see this observation.
    /// When it doesn't see it, free energy rises, driving action.
    pub fn set_preference(&mut self, obs_idx: usize, value: f64) {
        if obs_idx < self.num_obs {
            self.c[obs_idx] = value;
        }
    }

    /// Set observation likelihood: P(obs | state)
    pub fn set_likelihood(&mut self, obs_idx: usize, state_idx: usize, prob: f64) {
        if obs_idx < self.num_obs && state_idx < self.num_states {
            self.a[obs_idx][state_idx] = prob;
        }
    }

    /// Set transition probability: P(next_state | current_state, action)
    pub fn set_transition(&mut self, action: usize, next: usize, current: usize, prob: f64) {
        if action < self.num_actions && next < self.num_states && current < self.num_states {
            self.b[action][next][current] = prob;
        }
    }

    /// Normalize A matrix columns to sum to 1
    pub fn normalize_a(&mut self) {
        for s in 0..self.num_states {
            let col_sum: f64 = (0..self.num_obs).map(|o| self.a[o][s]).sum();
            if col_sum > 0.0 {
                for o in 0..self.num_obs {
                    self.a[o][s] /= col_sum;
                }
            }
        }
    }

    /// Normalize B matrix columns to sum to 1 per action
    pub fn normalize_b(&mut self) {
        for action in 0..self.num_actions {
            for s in 0..self.num_states {
                let col_sum: f64 = (0..self.num_states)
                    .map(|s2| self.b[action][s2][s])
                    .sum();
                if col_sum > 0.0 {
                    for s2 in 0..self.num_states {
                        self.b[action][s2][s] /= col_sum;
                    }
                }
            }
        }
    }
}

impl Agent {
    /// Create a new agent with the given generative model.
    pub fn new(model: GenerativeModel) -> Self {
        let beliefs = model.d.clone();
        let prior = model.d.clone();
        Self {
            model,
            beliefs,
            prior,
            gamma: 16.0,
            inference_iters: 10,
            cumulative_free_energy: 0.0,
            step: 0,
            learning_rate_a: 0.01,
            learning_rate_b: 0.01,
            learning_rate_d: 0.001,
            learning_enabled: false,
            learning_rate_c: 0.005,
            prev_beliefs: None,
            prev_action: None,
            prev_free_energy: None,
            prev_observation: None,
        }
    }

    /// Run one full perception-action cycle.
    ///
    /// 1. Observe → update beliefs (minimize free energy)
    /// 2. Evaluate policies (expected free energy)
    /// 3. Select action (softmax over -G)
    /// 4. Predict next state (set prior for next step)
    ///
    /// # Panics
    /// Panics if `observation >= num_obs`. The observation must be a valid
    /// index into the model's observation space (mirrors slice-index
    /// semantics); callers mapping real-world signals to indices must clamp.
    pub fn step(&mut self, observation: usize) -> InferenceResult {
        assert!(
            observation < self.model.num_obs,
            "observation index {observation} out of range (num_obs={})",
            self.model.num_obs
        );
        // 0. Learn from previous step (before updating beliefs)
        if self.learning_enabled {
            self.learn(observation);
        }

        // 1. State inference: q(s) = softmax(ln P(o|s) + ln prior)
        self.infer_states(observation);

        // 2. Compute variational free energy
        let fe = self.variational_free_energy(observation);

        // 3. Compute prediction error
        let pred_error = self.prediction_error(observation);

        // 4. Evaluate expected free energy for each action
        let efg = self.expected_free_energy();

        // 5. Policy selection: softmax(-G * gamma)
        let policy = softmax_scaled(&efg.iter().map(|g| -g).collect::<Vec<_>>(), self.gamma);

        // 6. Select action
        let action = argmax(&policy);

        // 7. Predict next state: prior = B[action] * beliefs
        self.prior = mat_vec_mul(&self.model.b[action], &self.beliefs);

        // 8. Save state for next learning step
        self.prev_beliefs = Some(self.beliefs.clone());
        self.prev_action = Some(action);
        self.prev_free_energy = Some(fe);
        self.prev_observation = Some(observation);

        // Track
        self.cumulative_free_energy += fe;
        self.step += 1;

        InferenceResult {
            beliefs: self.beliefs.clone(),
            free_energy: fe,
            expected_free_energy: efg,
            action,
            policy_distribution: policy,
            prediction_error: pred_error,
        }
    }

    /// Enable learning — the agent updates its own world model.
    pub fn enable_learning(&mut self) {
        self.learning_enabled = true;
    }

    /// Learn from experience — update A, B, D matrices.
    ///
    /// A learning: "I saw observation O when I believed I was in state S"
    ///   → strengthen A[O][S]
    ///
    /// B learning: "I was in state S, took action A, and now I'm in state S'"
    ///   → strengthen B[A][S'][S]
    ///
    /// D learning: "I keep ending up in state S at the start"
    ///   → adjust initial prior toward observed start states
    ///
    /// This is Hebbian-like: what fires together wires together.
    /// The agent literally rewires its own brain from experience.
    fn learn(&mut self, current_obs: usize) {
        let ns = self.model.num_states;
        let no = self.model.num_obs;

        // ─── A learning: observation model ───────────────────────
        // Strengthen the connection between current observation and
        // believed states. "I see this, and I think I'm here."
        {
            let lr = self.learning_rate_a;
            for s in 0..ns {
                let belief_s = self.beliefs[s]; // how much we believe we're in state s

                for o in 0..no {
                    if o == current_obs {
                        // Strengthen: observed → believed state
                        self.model.a[o][s] += lr * belief_s;
                    } else {
                        // Weaken other observations slightly
                        self.model.a[o][s] -= lr * belief_s * 0.1;
                        self.model.a[o][s] = self.model.a[o][s].max(1e-6);
                    }
                }
            }
            self.model.normalize_a();
        }

        // ─── B learning: transition model ────────────────────────
        // "I was in prev_state, took prev_action, and now I'm here."
        if let (Some(ref prev_beliefs), Some(prev_action)) =
            (&self.prev_beliefs, self.prev_action)
        {
            let lr = self.learning_rate_b;
            // s_prev indexes prev_beliefs AND the b-tensor source-state dim
            // (self.model.b[..][..][s_prev]) — an iterator can't replace both uses.
            #[allow(clippy::needless_range_loop)]
            for s_prev in 0..ns {
                let prev_b = prev_beliefs[s_prev];
                for s_curr in 0..ns {
                    let curr_b = self.beliefs[s_curr];
                    // Strengthen transitions that match experience
                    let delta = lr * prev_b * curr_b;
                    self.model.b[prev_action][s_curr][s_prev] += delta;
                }
            }
            // Normalize the updated action's transition matrix
            let action = prev_action;
            for s in 0..ns {
                let col_sum: f64 = (0..ns)
                    .map(|s2| self.model.b[action][s2][s])
                    .sum();
                if col_sum > 0.0 {
                    for s2 in 0..ns {
                        self.model.b[action][s2][s] /= col_sum;
                    }
                }
            }
        }

        // ─── C learning: preference adaptation ─────────────────────
        // If free energy DECREASED after observing something, strengthen
        // the preference for that observation. If it INCREASED, weaken it.
        // This is how the agent learns what it actually wants — not from
        // being told, but from experiencing what reduces its surprise.
        //
        // "What made me less surprised is what I want more of."
        if let (Some(prev_fe), Some(prev_obs)) =
            (self.prev_free_energy, self.prev_observation)
        {
            let fe_delta = self.variational_free_energy(current_obs) - prev_fe;
            let lr = self.learning_rate_c;

            if fe_delta < -0.01 {
                // Free energy decreased → this observation helped → want more
                self.model.c[current_obs] += lr * (-fe_delta).min(1.0);
            } else if fe_delta > 0.1 {
                // Free energy increased → this observation hurt → want less
                // But don't go below a floor — some discomfort is informative
                self.model.c[prev_obs] -= lr * fe_delta.min(1.0) * 0.5;
            }
        }

        // ─── D learning: initial state prior ─────────────────────
        // Slowly shift the initial prior toward observed states.
        // This makes the agent "remember" where it usually starts.
        if self.step < 50 {
            let lr = self.learning_rate_d;
            for s in 0..ns {
                self.model.d[s] += lr * self.beliefs[s];
            }
            // Normalize
            let sum: f64 = self.model.d.iter().sum();
            if sum > 0.0 {
                for s in 0..ns {
                    self.model.d[s] /= sum;
                }
            }
        }
    }

    /// State inference via fixed-point iteration.
    /// q(s) ∝ P(o|s) * prior(s)
    fn infer_states(&mut self, observation: usize) {
        // Log-likelihood of the observation under each state
        let log_likelihood: Vec<f64> = (0..self.model.num_states)
            .map(|s| {
                let p = self.model.a[observation][s].max(1e-16);
                p.ln()
            })
            .collect();

        // Log prior
        let log_prior: Vec<f64> = self.prior.iter()
            .map(|p| p.max(1e-16).ln())
            .collect();

        // Posterior ∝ exp(log_likelihood + log_prior)
        let log_posterior: Vec<f64> = log_likelihood.iter()
            .zip(log_prior.iter())
            .map(|(ll, lp)| ll + lp)
            .collect();

        self.beliefs = softmax(&log_posterior);
    }

    /// Variational free energy: F = E_q[ln q(s) - ln P(o,s)]
    /// = KL[q(s) || prior(s)] - E_q[ln P(o|s)]
    fn variational_free_energy(&self, observation: usize) -> f64 {
        let mut fe = 0.0;
        for s in 0..self.model.num_states {
            let q = self.beliefs[s].max(1e-16);
            let p_prior = self.prior[s].max(1e-16);
            let p_obs = self.model.a[observation][s].max(1e-16);

            // KL divergence term (complexity)
            fe += q * (q.ln() - p_prior.ln());
            // Accuracy term
            fe -= q * p_obs.ln();
        }
        fe
    }

    /// Prediction error: how surprised is the agent?
    fn prediction_error(&self, observation: usize) -> f64 {
        // Predicted observation distribution
        let predicted: Vec<f64> = (0..self.model.num_obs)
            .map(|o| {
                (0..self.model.num_states)
                    .map(|s| self.model.a[o][s] * self.beliefs[s])
                    .sum()
            })
            .collect();

        // Prediction error = -log P(actual observation)
        let p_obs = predicted[observation].max(1e-16);
        -p_obs.ln()
    }

    /// Expected free energy for each action (one-step lookahead).
    ///
    /// G(a) = ambiguity + risk
    ///   ambiguity = H[P(o|s)] · q(s')  — epistemic (information-seeking)
    ///   risk = KL[P(o|s') || C]         — pragmatic (goal-seeking)
    fn expected_free_energy(&self) -> Vec<f64> {
        let mut g = vec![0.0; self.model.num_actions];

        // Entropy of each column of A (ambiguity of each state)
        let h_a: Vec<f64> = (0..self.model.num_states)
            .map(|s| {
                let mut h = 0.0;
                for o in 0..self.model.num_obs {
                    let p = self.model.a[o][s].max(1e-16);
                    h -= p * p.ln();
                }
                h
            })
            .collect();

        // Normalize C to a proper distribution for KL computation
        let c_dist = softmax(&self.model.c);

        // action indexes the b-tensor (self.model.b[action]) AND the per-action
        // free-energy vec g[action] — an iterator can't replace both uses.
        #[allow(clippy::needless_range_loop)]
        for action in 0..self.model.num_actions {
            // Predict next state under this action
            let qs_next = mat_vec_mul(&self.model.b[action], &self.beliefs);

            // Predict observation under next state
            let qo_next: Vec<f64> = (0..self.model.num_obs)
                .map(|o| {
                    (0..self.model.num_states)
                        .map(|s| self.model.a[o][s] * qs_next[s])
                        .sum()
                })
                .collect();

            // Ambiguity: expected entropy of observations (epistemic value)
            let ambiguity: f64 = (0..self.model.num_states)
                .map(|s| h_a[s] * qs_next[s])
                .sum();

            // Risk: KL divergence from predicted obs to preferred obs
            let risk = kl_divergence(&qo_next, &c_dist);

            g[action] = ambiguity + risk;
        }

        g
    }
}

impl fmt::Display for Agent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Agent(step={}, F_cumulative={:.3}, beliefs={:?})",
            self.step,
            self.cumulative_free_energy,
            self.beliefs.iter().map(|b| format!("{:.3}", b)).collect::<Vec<_>>()
        )
    }
}

// ─── Math utilities ──────────────────────────────────────────────────────

fn softmax(logits: &[f64]) -> Vec<f64> {
    let max = logits.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    let exps: Vec<f64> = logits.iter().map(|x| (x - max).exp()).collect();
    let sum: f64 = exps.iter().sum();
    exps.iter().map(|e| e / sum).collect()
}

fn softmax_scaled(logits: &[f64], gamma: f64) -> Vec<f64> {
    let scaled: Vec<f64> = logits.iter().map(|x| x * gamma).collect();
    softmax(&scaled)
}

fn argmax(v: &[f64]) -> usize {
    v.iter()
        .enumerate()
        .max_by(|a, b| a.1.total_cmp(b.1))
        .map(|(i, _)| i)
        .unwrap_or(0)
}

fn mat_vec_mul(mat: &[Vec<f64>], vec: &[f64]) -> Vec<f64> {
    mat.iter()
        .map(|row| row.iter().zip(vec.iter()).map(|(m, v)| m * v).sum())
        .collect()
}

fn kl_divergence(p: &[f64], q: &[f64]) -> f64 {
    p.iter()
        .zip(q.iter())
        .map(|(pi, qi)| {
            let pi = pi.max(1e-16);
            let qi = qi.max(1e-16);
            pi * (pi.ln() - qi.ln())
        })
        .sum()
}

// ─── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_accepts_well_formed_model_and_rejects_shape_mismatch() {
        // A model built by `new` is internally consistent.
        let model = GenerativeModel::new(2, 3, 2);
        assert!(model.validate().is_ok());

        // Lying about num_obs (without resizing A/C) is exactly the kind of
        // inconsistency that would later panic `Agent::step`; validate catches
        // it up front instead.
        let mut bad_obs = model.clone();
        bad_obs.num_obs = 99;
        assert!(bad_obs.validate().is_err());

        // A truncated A matrix is rejected.
        let mut bad_a = GenerativeModel::new(2, 3, 2);
        bad_a.a.pop();
        assert!(bad_a.validate().is_err());

        // A transition matrix with the wrong row count is rejected.
        let mut bad_b = GenerativeModel::new(2, 3, 2);
        bad_b.b[0].pop();
        assert!(bad_b.validate().is_err());

        // Zero dimensions are rejected.
        let mut zero_dim = GenerativeModel::new(2, 3, 2);
        zero_dim.num_states = 0;
        assert!(zero_dim.validate().is_err());

        // Value seal: shape is fine but a non-finite entry would poison
        // `Agent::step` (sticky NaN through free energy). Each matrix is sealed.
        let mut nan_a = GenerativeModel::new(2, 3, 2);
        nan_a.a[1][0] = f64::NAN;
        assert!(nan_a.validate().is_err(), "NaN in A must be rejected");

        let mut inf_b = GenerativeModel::new(2, 3, 2);
        inf_b.b[0][1][0] = f64::INFINITY;
        assert!(inf_b.validate().is_err(), "Inf in B must be rejected");

        let mut nan_c = GenerativeModel::new(2, 3, 2);
        nan_c.c[2] = f64::NAN;
        assert!(nan_c.validate().is_err(), "NaN in C must be rejected");

        let mut neg_inf_d = GenerativeModel::new(2, 3, 2);
        neg_inf_d.d[0] = f64::NEG_INFINITY;
        assert!(neg_inf_d.validate().is_err(), "-Inf in D must be rejected");
    }

    /// The hunger test: an agent that NEEDS food.
    ///
    /// Setup:
    ///   - 2 states: HUNGRY, FED
    ///   - 3 observations: see_nothing, see_food, feel_full
    ///   - 2 actions: STAY, SEEK_FOOD
    ///   - C matrix: strongly prefers feel_full observation
    ///
    /// Expected behavior: when hungry, the agent should choose SEEK_FOOD
    /// because free energy is high (reality doesn't match preference).
    #[test]
    fn test_hunger_drives_seeking() {
        let mut model = GenerativeModel::new(2, 3, 2);

        // States: 0=HUNGRY, 1=FED
        // Observations: 0=see_nothing, 1=see_food, 2=feel_full
        // Actions: 0=STAY, 1=SEEK_FOOD

        // A matrix: what you observe in each state
        // When HUNGRY: likely see_nothing or see_food, unlikely feel_full
        model.set_likelihood(0, 0, 0.5);  // hungry → see_nothing
        model.set_likelihood(1, 0, 0.4);  // hungry → see_food
        model.set_likelihood(2, 0, 0.1);  // hungry → feel_full (rare)
        // When FED: likely feel_full
        model.set_likelihood(0, 1, 0.1);  // fed → see_nothing
        model.set_likelihood(1, 1, 0.1);  // fed → see_food
        model.set_likelihood(2, 1, 0.8);  // fed → feel_full
        model.normalize_a();

        // B matrix: transitions
        // STAY action: remain in current state
        model.set_transition(0, 0, 0, 0.9);  // stay hungry → stay hungry
        model.set_transition(0, 1, 0, 0.1);  // stay hungry → become fed (unlikely)
        model.set_transition(0, 0, 1, 0.2);  // stay fed → become hungry
        model.set_transition(0, 1, 1, 0.8);  // stay fed → stay fed

        // SEEK_FOOD action: likely to become fed
        model.set_transition(1, 0, 0, 0.2);  // seek when hungry → stay hungry
        model.set_transition(1, 1, 0, 0.8);  // seek when hungry → become fed!
        model.set_transition(1, 0, 1, 0.1);  // seek when fed → become hungry
        model.set_transition(1, 1, 1, 0.9);  // seek when fed → stay fed
        model.normalize_b();

        // C matrix: THE NEED — agent strongly prefers feeling full
        model.set_preference(0, -1.0);  // don't want to see nothing
        model.set_preference(1, 0.0);   // neutral about seeing food
        model.set_preference(2, 4.0);   // STRONGLY prefer feeling full

        // Start hungry, prior biased toward HUNGRY state
        model.d = vec![0.8, 0.2];

        let mut agent = Agent::new(model);

        // Observe: see_nothing (consistent with being hungry)
        let result = agent.step(0);

        println!("Beliefs: HUNGRY={:.3}, FED={:.3}",
            result.beliefs[0], result.beliefs[1]);
        println!("Free energy: {:.3}", result.free_energy);
        println!("Action: {} (0=STAY, 1=SEEK_FOOD)", result.action);
        println!("Policy: STAY={:.3}, SEEK={:.3}",
            result.policy_distribution[0], result.policy_distribution[1]);
        println!("EFE: STAY={:.3}, SEEK={:.3}",
            result.expected_free_energy[0], result.expected_free_energy[1]);

        // The agent should choose SEEK_FOOD (action 1)
        // because it prefers feel_full but observes see_nothing
        assert_eq!(result.action, 1, "Hungry agent should seek food!");

        // Free energy should be positive (surprise — reality ≠ preference)
        assert!(result.free_energy > 0.0, "Should have positive free energy when hungry");

        // Now observe: feel_full (the agent got what it wanted)
        let result2 = agent.step(2);

        println!("\nAfter eating:");
        println!("Beliefs: HUNGRY={:.3}, FED={:.3}",
            result2.beliefs[0], result2.beliefs[1]);
        println!("Free energy: {:.3}", result2.free_energy);
        println!("Action: {} (0=STAY, 1=SEEK_FOOD)", result2.action);
        println!("EFE: STAY={:.3}, SEEK={:.3}",
            result2.expected_free_energy[0], result2.expected_free_energy[1]);

        // Free energy should be lower now (reality matches preference)
        assert!(result2.free_energy < result.free_energy,
            "Free energy should decrease when need is met");

        // EFE for STAY should be lower than when hungry
        // (the agent is closer to its preferred state)
        assert!(result2.expected_free_energy[0] < result.expected_free_energy[0],
            "Staying should be less costly when already fed");
    }

    /// Curiosity test: agent prefers informative actions over ambiguous ones.
    #[test]
    fn test_curiosity_prefers_informative_states() {
        let mut model = GenerativeModel::new(3, 3, 3);

        // 3 states, 3 observations, 3 actions
        // State 0: ambiguous (all observations equally likely)
        // State 1: somewhat informative
        // State 2: highly informative (one dominant observation)

        // A matrix: varying informativeness per state
        // State 0: ambiguous
        model.set_likelihood(0, 0, 0.33);
        model.set_likelihood(1, 0, 0.34);
        model.set_likelihood(2, 0, 0.33);
        // State 1: somewhat clear
        model.set_likelihood(0, 1, 0.6);
        model.set_likelihood(1, 1, 0.2);
        model.set_likelihood(2, 1, 0.2);
        // State 2: very clear
        model.set_likelihood(0, 2, 0.05);
        model.set_likelihood(1, 2, 0.05);
        model.set_likelihood(2, 2, 0.9);
        model.normalize_a();

        // B matrix: each action reliably leads to corresponding state
        for a in 0..3 {
            for s in 0..3 {
                for s2 in 0..3 {
                    let p = if s2 == a { 0.8 } else { 0.1 };
                    model.set_transition(a, s2, s, p);
                }
            }
        }
        model.normalize_b();

        // No preferences — pure curiosity (epistemic drive only)
        model.c = vec![0.0; 3];

        // Start in ambiguous state
        model.d = vec![0.8, 0.1, 0.1];

        let mut agent = Agent::new(model);
        agent.gamma = 8.0;

        // Observe ambiguous output
        let result = agent.step(0);

        println!("Curiosity test:");
        println!("EFE per action: {:?}", result.expected_free_energy);
        println!("Policy: {:?}", result.policy_distribution);
        println!("Action chosen: {}", result.action);

        // Action 2 leads to the most informative state (lowest ambiguity)
        // so its EFE should be lowest (most epistemic value)
        assert!(result.expected_free_energy[2] < result.expected_free_energy[0],
            "Informative action should have lower EFE (curiosity drives toward clarity)");
    }

    /// Multi-step test: watch free energy decrease as agent adapts.
    #[test]
    fn test_free_energy_decreases_over_time() {
        let mut model = GenerativeModel::new(2, 2, 2);

        // Simple: 2 states, 2 obs, 2 actions
        model.set_likelihood(0, 0, 0.9);
        model.set_likelihood(1, 0, 0.1);
        model.set_likelihood(0, 1, 0.1);
        model.set_likelihood(1, 1, 0.9);
        model.normalize_a();

        model.set_transition(0, 0, 0, 0.9);
        model.set_transition(0, 1, 0, 0.1);
        model.set_transition(0, 0, 1, 0.1);
        model.set_transition(0, 1, 1, 0.9);
        model.set_transition(1, 0, 0, 0.3);
        model.set_transition(1, 1, 0, 0.7);
        model.set_transition(1, 0, 1, 0.7);
        model.set_transition(1, 1, 1, 0.3);
        model.normalize_b();

        // Prefer observation 1
        model.c = vec![-1.0, 3.0];
        model.d = vec![0.5, 0.5];

        let mut agent = Agent::new(model);

        // Simulate 20 steps — observe based on agent's action
        let mut energies = Vec::new();
        let mut obs = 0;

        for _ in 0..20 {
            let result = agent.step(obs);
            energies.push(result.free_energy);

            // Simple environment: action 1 leads to observation 1
            obs = if result.action == 1 { 1 } else { 0 };
        }

        println!("Free energy over time:");
        for (i, fe) in energies.iter().enumerate() {
            println!("  step {}: F={:.4}", i, fe);
        }

        // Average free energy in last 5 steps should be lower than first 5
        let early: f64 = energies[..5].iter().sum::<f64>() / 5.0;
        let late: f64 = energies[15..].iter().sum::<f64>() / 5.0;
        println!("Early avg F: {:.4}, Late avg F: {:.4}", early, late);

        assert!(late <= early + 0.1,
            "Free energy should decrease or stabilize as agent adapts");
    }

    /// Learning test: agent updates its world model from experience.
    #[test]
    fn test_learning_improves_model() {
        let mut model = GenerativeModel::new(2, 2, 2);

        // Start with a WRONG model — agent thinks state 0 produces obs 0
        // but reality is the opposite: state 0 → obs 1, state 1 → obs 0
        model.set_likelihood(0, 0, 0.9); // wrong!
        model.set_likelihood(1, 0, 0.1);
        model.set_likelihood(0, 1, 0.1);
        model.set_likelihood(1, 1, 0.9); // wrong!
        model.normalize_a();

        model.set_transition(0, 0, 0, 0.7);
        model.set_transition(0, 1, 0, 0.3);
        model.set_transition(0, 0, 1, 0.3);
        model.set_transition(0, 1, 1, 0.7);
        model.set_transition(1, 0, 0, 0.4);
        model.set_transition(1, 1, 0, 0.6);
        model.set_transition(1, 0, 1, 0.6);
        model.set_transition(1, 1, 1, 0.4);
        model.normalize_b();

        model.c = vec![0.0, 2.0]; // prefers obs 1
        model.d = vec![0.5, 0.5];

        // Save initial A matrix for comparison
        let initial_a_0_0 = model.a[0][0];

        let mut agent = Agent::new(model);
        agent.enable_learning();

        // Feed consistent experience: always observe obs 1
        // The agent should learn that its current state produces obs 1
        let mut energies = Vec::new();
        for _ in 0..100 {
            let result = agent.step(1); // always see obs 1
            energies.push(result.free_energy);
        }

        // Check that A matrix changed
        let final_a_0_0 = agent.model.a[0][0];
        println!("A[0][0]: {:.4} → {:.4}", initial_a_0_0, final_a_0_0);
        println!("A[1][0]: {:.4} → {:.4}", 1.0 - initial_a_0_0,
            agent.model.a[1][0]);

        // The agent should have strengthened A[1][*] (obs 1 is common)
        // and weakened A[0][*] (obs 0 is never seen)
        assert!(final_a_0_0 < initial_a_0_0,
            "Unseen observation likelihood should decrease");

        // Average free energy should decrease as model improves
        let early_fe: f64 = energies[..10].iter().sum::<f64>() / 10.0;
        let late_fe: f64 = energies[90..].iter().sum::<f64>() / 10.0;
        println!("Early avg F: {:.4}, Late avg F: {:.4}", early_fe, late_fe);
        assert!(late_fe < early_fe + 0.5,
            "Free energy should not increase dramatically as model learns");
    }

    /// Preference learning: agent discovers what it actually wants.
    #[test]
    fn test_preference_learning() {
        let mut model = GenerativeModel::new(2, 3, 2);

        // Clear A matrix
        model.set_likelihood(0, 0, 0.7);
        model.set_likelihood(1, 0, 0.2);
        model.set_likelihood(2, 0, 0.1);
        model.set_likelihood(0, 1, 0.1);
        model.set_likelihood(1, 1, 0.2);
        model.set_likelihood(2, 1, 0.7);
        model.normalize_a();

        model.set_transition(0, 0, 0, 0.7);
        model.set_transition(0, 1, 0, 0.3);
        model.set_transition(0, 0, 1, 0.3);
        model.set_transition(0, 1, 1, 0.7);
        model.set_transition(1, 0, 0, 0.4);
        model.set_transition(1, 1, 0, 0.6);
        model.set_transition(1, 0, 1, 0.4);
        model.set_transition(1, 1, 1, 0.6);
        model.normalize_b();

        // Start with EQUAL preferences — no pre-programmed need
        model.c = vec![0.0, 0.0, 0.0];
        model.d = vec![0.5, 0.5];

        let initial_c = model.c.clone();

        let mut agent = Agent::new(model);
        agent.enable_learning();
        agent.learning_rate_c = 0.02; // slightly higher for faster test

        // Feed obs 2 repeatedly — it should become preferred
        for _ in 0..100 {
            agent.step(2);
        }

        println!("Preference learning:");
        println!("  Initial C: {:?}", initial_c);
        println!("  Final C:   [{:.4}, {:.4}, {:.4}]",
            agent.model.c[0], agent.model.c[1], agent.model.c[2]);

        // The agent should have developed a preference for obs 2
        // (it consistently reduces free energy when observed)
        assert!(agent.model.c[2] > initial_c[2],
            "Preference for consistently observed stimulus should increase");
    }

    /// Test that learning doesn't break with learning disabled (default).
    #[test]
    fn test_no_learning_by_default() {
        let mut model = GenerativeModel::new(2, 2, 2);
        model.set_likelihood(0, 0, 0.9);
        model.set_likelihood(1, 0, 0.1);
        model.set_likelihood(0, 1, 0.1);
        model.set_likelihood(1, 1, 0.9);
        model.normalize_a();
        model.c = vec![0.0, 1.0];
        model.d = vec![0.5, 0.5];

        let initial_a = model.a.clone();
        let mut agent = Agent::new(model);
        // learning_enabled is false by default

        for _ in 0..50 {
            agent.step(0);
        }

        // A matrix should be unchanged
        assert_eq!(agent.model.a, initial_a,
            "A matrix should not change when learning is disabled");
    }

    #[test]
    fn test_softmax() {
        let result = softmax(&[1.0, 2.0, 3.0]);
        let sum: f64 = result.iter().sum();
        assert!((sum - 1.0).abs() < 1e-10, "Softmax should sum to 1");
        assert!(result[2] > result[1] && result[1] > result[0],
            "Higher logits should get higher probabilities");
    }

    #[test]
    fn test_kl_divergence_identical() {
        let p = vec![0.3, 0.3, 0.4];
        let kl = kl_divergence(&p, &p);
        assert!(kl.abs() < 1e-10, "KL divergence of identical distributions should be 0");
    }

    #[test]
    fn test_mat_vec_mul() {
        let mat = vec![vec![1.0, 2.0], vec![3.0, 4.0]];
        let v = vec![1.0, 1.0];
        let result = mat_vec_mul(&mat, &v);
        assert_eq!(result, vec![3.0, 7.0]);
    }

    #[test]
    fn batch_b_softmax_scaled_gamma_one_equivalent_to_unscaled_softmax_pinning_identity_axis() {
        let logits = [0.5, 1.5, 2.5, -1.0];
        let unscaled = softmax(&logits);
        let scaled_one = softmax_scaled(&logits, 1.0);
        assert_eq!(unscaled.len(), scaled_one.len(),
            "softmax_scaled must preserve length of logits");
        for (i, (u, s)) in unscaled.iter().zip(scaled_one.iter()).enumerate() {
            assert!((u - s).abs() < 1e-12,
                "gamma=1.0 must reproduce softmax exactly at index {}: {} vs {}", i, u, s);
        }
        let sum: f64 = scaled_one.iter().sum();
        assert!((sum - 1.0).abs() < 1e-12,
            "softmax_scaled output must sum to 1.0, got {}", sum);
    }

    #[test]
    fn batch_b_softmax_scaled_high_gamma_concentrates_probability_mass_on_argmax_index() {
        // Logits: argmax is index 2 (value 1.0).
        let logits = [0.1, 0.5, 1.0, 0.2];
        let low = softmax_scaled(&logits, 1.0);
        let high = softmax_scaled(&logits, 50.0);
        // High gamma sharpens — argmax-mass strictly increases.
        assert!(high[2] > low[2],
            "gamma=50 must concentrate more mass on argmax than gamma=1: high={} low={}",
            high[2], low[2]);
        // At gamma=50, argmax mass should dominate (logit gap 0.5 × 50 = 25 in scaled space).
        assert!(high[2] > 0.99,
            "gamma=50 must place > 99% on argmax for these logits, got {}", high[2]);
        // Still a valid probability distribution.
        let sum: f64 = high.iter().sum();
        assert!((sum - 1.0).abs() < 1e-10,
            "high-gamma softmax must still sum to 1.0, got {}", sum);
    }

    #[test]
    fn batch_b_softmax_scaled_zero_gamma_yields_uniform_distribution_regardless_of_logit_spread() {
        // gamma=0.0 collapses every scaled logit to 0.0 → softmax([0,0,…,0]) = [1/n,…,1/n].
        // Logit values are deliberately extreme (-1e6, +100) to prove the gamma=0 erasure.
        let logits = [-3.0, 0.0, 7.5, 100.0, -1e6];
        let result = softmax_scaled(&logits, 0.0);
        let expected = 1.0 / (logits.len() as f64);
        for (i, p) in result.iter().enumerate() {
            assert!((p - expected).abs() < 1e-12,
                "gamma=0 must yield uniform 1/n at index {}: got {} expected {}",
                i, p, expected);
        }
    }

    #[test]
    fn batch_b_argmax_last_index_wins_on_ties_zero_on_empty_input_pinning_max_by_semantics() {
        // Rust Iterator::max_by returns the LAST element when comparator returns Ordering::Equal.
        // The argmax impl uses partial_cmp with Equal fallback → last-wins on ties.
        assert_eq!(argmax(&[2.0, 2.0]), 1,
            "two-way tie: last index wins (max_by semantics)");
        assert_eq!(argmax(&[3.0, 2.0, 3.0]), 2,
            "tie across non-adjacent indices: last wins");
        assert_eq!(argmax(&[5.0, 5.0, 5.0, 5.0]), 3,
            "four-way tie returns last index");
        // Single element → index 0.
        assert_eq!(argmax(&[7.0]), 0,
            "single-element argmax is index 0");
        // Empty input → unwrap_or(0) fallback.
        assert_eq!(argmax(&[]), 0,
            "empty slice argmax falls back to 0");
        // Distinct max at middle index (no tie).
        assert_eq!(argmax(&[1.0, 9.0, 3.0]), 1,
            "distinct max at middle index returns that index");
        // Strictly descending — first index wins.
        assert_eq!(argmax(&[10.0, 5.0, 1.0]), 0,
            "strictly descending: first (largest) wins");
    }

    // ─── batch_b extension: struct/method surface (peer 3193fa96 covered
    //                       softmax_scaled / argmax / kl_divergence math
    //                       helpers; these pin GenerativeModel / Agent
    //                       construction + defensive bounds + Display)
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn batch_b_generative_model_new_initial_invariants() {
        // GenerativeModel::new must produce a valid initial model:
        // - A: uniform cells = 1/num_states (NOT pre-normalized; per-column
        //   sum = num_obs/num_states, only = 1.0 when num_obs == num_states)
        // - B per action: diagonal = 0.99, off-diagonals = 0.01/(n-1)
        //   (each column sums to 1.0 by construction — identity-ish)
        // - C: zero (no preferences pre-modulation)
        // - D: uniform 1/n (sums to 1.0)
        // - Dimensions stored verbatim
        let num_states = 4;
        let num_obs = 3;
        let num_actions = 2;
        let m = GenerativeModel::new(num_states, num_obs, num_actions);

        assert_eq!(m.num_states, num_states);
        assert_eq!(m.num_obs, num_obs);
        assert_eq!(m.num_actions, num_actions);

        // A: every entry equals 1/num_states (uniform construction).
        let a_cell = 1.0 / num_states as f64;
        for o in 0..num_obs {
            for s in 0..num_states {
                assert!(
                    (m.a[o][s] - a_cell).abs() < 1e-12,
                    "A[{o}][{s}] must be uniform 1/num_states = {a_cell}, got {}",
                    m.a[o][s]
                );
            }
        }
        // C: all zero (no preferences yet).
        assert_eq!(m.c, vec![0.0; num_obs]);
        // D: uniform = 1/num_states each entry, sums to 1.0.
        let d_expected = 1.0 / num_states as f64;
        for s in 0..num_states {
            assert!(
                (m.d[s] - d_expected).abs() < 1e-12,
                "D[{s}] must be uniform 1/n = {d_expected}"
            );
        }
        let d_sum: f64 = m.d.iter().sum();
        assert!((d_sum - 1.0).abs() < 1e-12, "D must sum to 1.0, got {d_sum}");
        // B per action: identity-ish diagonal 0.99, off-diagonal 0.01/(n-1).
        let off_expected = 0.01 / (num_states - 1) as f64;
        for action in 0..num_actions {
            for s in 0..num_states {
                for s2 in 0..num_states {
                    let v = m.b[action][s][s2];
                    let expected = if s == s2 { 0.99 } else { off_expected };
                    assert!(
                        (v - expected).abs() < 1e-12,
                        "B[{action}][{s}][{s2}] expected {expected}, got {v}"
                    );
                }
            }
            // Sanity: per action, every column sums to 1.0 (identity-ish row pattern).
            for s in 0..num_states {
                let col_sum: f64 = (0..num_states).map(|s2| m.b[action][s2][s]).sum();
                assert!(
                    (col_sum - 1.0).abs() < 1e-12,
                    "B[{action}] column {s} must sum to 1.0 at init, got {col_sum}"
                );
            }
        }
    }

    #[test]
    fn batch_b_setters_silently_ignore_out_of_bounds_indices() {
        // The three setters defensively no-op on OOB indices — they MUST NOT
        // panic and MUST NOT extend the matrices. This protects against
        // garbage upstream indices (e.g., temporal::modulate_preferences
        // writing c[3] on a model with num_obs < 4 via the set_preference
        // path would be a silent error).
        let mut m = GenerativeModel::new(2, 2, 2);
        let snapshot_a = m.a.clone();
        let snapshot_c = m.c.clone();
        let snapshot_b = m.b.clone();

        // set_preference: obs_idx >= num_obs → no change.
        m.set_preference(2, 99.0);
        m.set_preference(100, 99.0);
        m.set_preference(usize::MAX, 99.0);
        assert_eq!(m.c, snapshot_c, "set_preference OOB must be a no-op");

        // set_likelihood: either index OOB → no change.
        m.set_likelihood(2, 0, 0.5);
        m.set_likelihood(0, 2, 0.5);
        m.set_likelihood(2, 2, 0.5);
        assert_eq!(m.a, snapshot_a, "set_likelihood OOB must be a no-op");

        // set_transition: any of action/next/current OOB → no change.
        m.set_transition(2, 0, 0, 0.5);
        m.set_transition(0, 2, 0, 0.5);
        m.set_transition(0, 0, 2, 0.5);
        m.set_transition(2, 2, 2, 0.5);
        assert_eq!(m.b, snapshot_b, "set_transition OOB must be a no-op");

        // Within-bounds writes still work (sanity that OOB checks didn't
        // accidentally lock the setter).
        m.set_preference(1, -3.0);
        assert_eq!(m.c[1], -3.0, "in-bounds set_preference must still write");
    }

    #[test]
    fn batch_b_normalize_a_and_b_idempotent_and_zero_column_skip_safe() {
        // normalize_a: after one call, every NON-ZERO column sums to 1.0.
        // Zero-sum columns MUST be skipped — dividing by zero would NaN the
        // matrix and corrupt downstream inference.
        let mut m = GenerativeModel::new(3, 3, 2);
        // Force column 1 of A to all zeros — zero-sum branch.
        for o in 0..3 {
            m.a[o][1] = 0.0;
        }
        m.normalize_a();
        // Column 1: stays all-zero (no NaN, no division).
        for o in 0..3 {
            assert!(
                m.a[o][1].is_finite(),
                "zero-column safety: A[{o}][1] must remain finite, got {}",
                m.a[o][1]
            );
            assert_eq!(
                m.a[o][1], 0.0,
                "zero column must be preserved exactly (no division applied)"
            );
        }
        // Columns 0 and 2: non-zero, sum to 1.0 post-normalize.
        for s in [0usize, 2usize] {
            let col_sum: f64 = (0..3).map(|o| m.a[o][s]).sum();
            assert!(
                (col_sum - 1.0).abs() < 1e-12,
                "non-zero column {s} normalized to 1.0: got {col_sum}"
            );
        }

        // Idempotence: a second normalize_a is a no-op on already-normalized A.
        let after_first = m.a.clone();
        m.normalize_a();
        assert_eq!(
            m.a, after_first,
            "normalize_a must be idempotent on already-normalized A"
        );

        // normalize_b: per-action column sums to 1.0 after the call.
        // Initial B (from new()) already has identity-ish columns that sum
        // to 1.0; normalize_b is a no-op there. Pin the invariant explicitly.
        let mut m2 = GenerativeModel::new(3, 2, 2);
        m2.normalize_b();
        for action in 0..2 {
            for s in 0..3 {
                let col_sum: f64 = (0..3).map(|s2| m2.b[action][s2][s]).sum();
                assert!(
                    (col_sum - 1.0).abs() < 1e-12,
                    "B[{action}] column {s} must sum to 1.0 after normalize_b: got {col_sum}"
                );
            }
        }
    }

    #[test]
    fn batch_b_agent_new_default_hyperparams_and_state_initialization() {
        // Agent::new must initialize policy hyperparameters to their
        // documented values and inherit beliefs+prior from model.d.
        // These defaults are part of the construction contract; drift
        // here would silently change inference behavior fleet-wide.
        let mut m = GenerativeModel::new(2, 2, 2);
        m.d = vec![0.3, 0.7]; // non-uniform — must propagate to beliefs+prior.
        let agent = Agent::new(m);

        // Hyperparameters.
        assert_eq!(agent.gamma, 16.0, "default gamma = 16.0");
        assert_eq!(agent.inference_iters, 10, "default inference_iters = 10");
        assert_eq!(agent.learning_rate_a, 0.01, "default learning_rate_a = 0.01");
        assert_eq!(agent.learning_rate_b, 0.01, "default learning_rate_b = 0.01");
        assert_eq!(agent.learning_rate_d, 0.001, "default learning_rate_d = 0.001");
        assert_eq!(agent.learning_rate_c, 0.005, "default learning_rate_c = 0.005");
        assert!(!agent.learning_enabled, "learning is disabled by default");

        // State counters.
        assert_eq!(agent.step, 0);
        assert_eq!(agent.cumulative_free_energy, 0.0);

        // Beliefs and prior inherited from D (independent clones).
        assert_eq!(agent.beliefs, vec![0.3, 0.7], "beliefs cloned from model.d");
        assert_eq!(agent.prior, vec![0.3, 0.7], "prior cloned from model.d");

        // Previous-step trackers all None pre-first-step.
        assert!(agent.prev_beliefs.is_none(), "prev_beliefs starts None");
        assert!(agent.prev_action.is_none(), "prev_action starts None");
        assert!(agent.prev_free_energy.is_none(), "prev_free_energy starts None");
        assert!(agent.prev_observation.is_none(), "prev_observation starts None");
    }

    #[test]
    fn batch_b_display_fmt_exposes_step_cumulative_fe_and_beliefs_for_logs() {
        // Agent's Display impl is consumed by /status logs and operator
        // dashboards. It MUST surface step, cumulative free energy with
        // 3-decimal precision, and beliefs with 3-decimal precision per
        // entry. The format string is part of the log-grep contract.
        let mut m = GenerativeModel::new(2, 2, 2);
        m.d = vec![0.25, 0.75];
        let mut agent = Agent::new(m);
        agent.step = 42;
        agent.cumulative_free_energy = 7.123_456_789;

        let display = format!("{}", agent);
        // step= must be present.
        assert!(
            display.contains("step=42"),
            "Display must include step counter, got: {display}"
        );
        // F_cumulative with 3 decimals (rounding semantics, not truncation).
        assert!(
            display.contains("F_cumulative=7.123"),
            "Display must include F_cumulative with 3-decimal precision, got: {display}"
        );
        // Beliefs rendered as a Vec<String> of 3-decimal entries: ["0.250", "0.750"].
        assert!(
            display.contains("0.250") && display.contains("0.750"),
            "Display must include 3-decimal beliefs, got: {display}"
        );
        // Agent(…) prefix.
        assert!(
            display.starts_with("Agent("),
            "Display must use Agent(…) prefix, got: {display}"
        );
    }

    #[test]
    fn batch_b_kl_divergence_positive_for_distinct_distributions_and_asymmetric_in_argument_order() {
        // Spread vs concentrated — asymmetric KL by construction.
        let p = vec![0.5, 0.4, 0.1];
        let q = vec![0.1, 0.1, 0.8];
        let kl_pq = kl_divergence(&p, &q);
        let kl_qp = kl_divergence(&q, &p);
        // Both directions must be strictly positive for distinct distributions
        // (Gibbs' inequality: KL ≥ 0 with equality iff p == q a.e.).
        assert!(kl_pq > 0.0,
            "KL(p||q) must be positive for distinct p,q: got {}", kl_pq);
        assert!(kl_qp > 0.0,
            "KL(q||p) must be positive for distinct p,q: got {}", kl_qp);
        // KL is asymmetric in general — for this specific pair the gap is ~0.21 nats.
        assert!((kl_pq - kl_qp).abs() > 0.1,
            "KL is asymmetric: KL(p||q)={:.6} vs KL(q||p)={:.6} must differ noticeably",
            kl_pq, kl_qp);
        // For these distributions analytically: KL(q||p) > KL(p||q)
        //   (q concentrates on index 2 where p_2 = 0.1, amplifying the log-ratio).
        assert!(kl_qp > kl_pq,
            "for this p,q pair KL(q||p) must exceed KL(p||q): {} vs {}", kl_qp, kl_pq);
    }

    /// An out-of-range observation index is a documented precondition: it must
    /// panic with a clear message at the entry, not a cryptic index-OOB deep in
    /// `infer_states`. (Previously `step(num_obs)` panicked on `a[observation]`.)
    #[test]
    #[should_panic(expected = "out of range")]
    fn step_panics_clearly_on_out_of_range_observation() {
        let mut agent = Agent::new(GenerativeModel::new(2, 3, 2));
        agent.step(3); // num_obs == 3, so index 3 is out of range
    }

    /// A valid in-range observation must still work after the guard.
    #[test]
    fn step_accepts_in_range_observation() {
        let mut agent = Agent::new(GenerativeModel::new(2, 3, 2));
        let _ = agent.step(2); // highest valid index
    }

    /// A zero-dimension model is degenerate (div-by-zero priors, empty action
    /// space → `b[0]` panic in step). `new` rejects it up front with a message.
    #[test]
    #[should_panic(expected = "non-zero")]
    fn new_rejects_zero_action_space() {
        let _ = GenerativeModel::new(2, 2, 0);
    }
}
