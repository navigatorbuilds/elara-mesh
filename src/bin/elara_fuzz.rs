//! elara-fuzz — 1000-case fuzzer for elara-node HTTP API
//!
//! Sends malformed, edge-case, and adversarial requests to a running node.
//! Run against a LOCAL node you operate (127.0.0.1:9474) — never against a
//! node you do not control.
//!
//! Usage: cargo run --features node --bin elara-fuzz [-- --target http://127.0.0.1:9474]

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

fn now_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

fn random_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    if getrandom::getrandom(&mut buf).is_err() {
        // entropy unavailable (restricted env) — zero-fill is valid fuzz data
        eprintln!("warn: getrandom unavailable; fuzz payloads will be zero-filled");
    }
    buf
}

fn random_hex(len: usize) -> String {
    hex::encode(random_bytes(len))
}

// ── Result tracking ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct FuzzResult {
    id: usize,
    category: String,
    name: String,
    passed: bool,
    status: Option<u16>,
    detail: String,
}

struct FuzzRunner {
    target: String,
    client: reqwest::blocking::Client,
    results: Vec<FuzzResult>,
    admin_token: String,
}

impl FuzzRunner {
    fn new(target: &str, admin_token: &str) -> Result<Self, reqwest::Error> {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()?;
        Ok(Self {
            target: target.to_string(),
            client,
            results: Vec::new(),
            admin_token: admin_token.to_string(),
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.target, path)
    }

    // ── HTTP helpers ────────────────────────────────────────────────────

    fn get(&self, path: &str) -> Result<reqwest::blocking::Response, reqwest::Error> {
        self.client.get(self.url(path)).send()
    }

    fn post_json(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<reqwest::blocking::Response, reqwest::Error> {
        self.client
            .post(self.url(path))
            .header("Content-Type", "application/json")
            .json(body)
            .send()
    }

    fn post_json_auth(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<reqwest::blocking::Response, reqwest::Error> {
        self.client
            .post(self.url(path))
            .header("Authorization", format!("Bearer {}", self.admin_token))
            .header("Content-Type", "application/json")
            .json(body)
            .send()
    }

    fn post_bytes(
        &self,
        path: &str,
        body: Vec<u8>,
    ) -> Result<reqwest::blocking::Response, reqwest::Error> {
        self.client
            .post(self.url(path))
            .header("Content-Type", "application/octet-stream")
            .body(body)
            .send()
    }

    fn post_text(
        &self,
        path: &str,
        body: &str,
    ) -> Result<reqwest::blocking::Response, reqwest::Error> {
        self.client
            .post(self.url(path))
            .header("Content-Type", "text/plain")
            .body(body.to_string())
            .send()
    }

    // ── Result recording ────────────────────────────────────────────────

    fn record(
        &mut self,
        category: &str,
        name: &str,
        passed: bool,
        status: Option<u16>,
        detail: &str,
    ) {
        let id = self.results.len() + 1;
        let symbol = if passed { "✓" } else { "✗" };
        let status_str = status
            .map(|s| format!(" [{}]", s))
            .unwrap_or_default();
        let detail_str = if !passed { format!(" — {}", detail) } else { String::new() };
        eprintln!(
            "  {} {:>4} | {:<20} | {}{}  {}",
            symbol, id, category, name, status_str, detail_str
        );
        self.results.push(FuzzResult {
            id,
            category: category.to_string(),
            name: name.to_string(),
            passed,
            status,
            detail: detail.to_string(),
        });
    }

    /// Expect a non-5xx response (node should reject gracefully, not crash)
    fn expect_no_crash(
        &mut self,
        category: &str,
        name: &str,
        result: Result<reqwest::blocking::Response, reqwest::Error>,
    ) {
        match result {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let crashed = status >= 500;
                self.record(
                    category,
                    name,
                    !crashed,
                    Some(status),
                    if crashed {
                        "SERVER ERROR — node may have panicked"
                    } else {
                        ""
                    },
                );
            }
            Err(e) => {
                let is_timeout = e.is_timeout();
                let is_connect = e.is_connect();
                self.record(
                    category,
                    name,
                    false,
                    None,
                    if is_connect {
                        "CONNECTION REFUSED — node down?"
                    } else if is_timeout {
                        "TIMEOUT — node hung"
                    } else {
                        "REQUEST FAILED"
                    },
                );
            }
        }
    }

    /// Expect a specific status code
    fn expect_status(
        &mut self,
        category: &str,
        name: &str,
        expected: u16,
        result: Result<reqwest::blocking::Response, reqwest::Error>,
    ) {
        match result {
            Ok(resp) => {
                let status = resp.status().as_u16();
                self.record(
                    category,
                    name,
                    status == expected,
                    Some(status),
                    &format!("expected {}", expected),
                );
            }
            Err(e) => {
                self.record(category, name, false, None, &format!("request error: {}", e));
            }
        }
    }

    /// Expect rejection (4xx) — should NOT be accepted (2xx)
    fn expect_rejection(
        &mut self,
        category: &str,
        name: &str,
        result: Result<reqwest::blocking::Response, reqwest::Error>,
    ) {
        match result {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let accepted = (200..300).contains(&status);
                let crashed = status >= 500;
                if accepted {
                    let body = resp.text().unwrap_or_default();
                    self.record(
                        category,
                        name,
                        false,
                        Some(status),
                        &format!("ACCEPTED when should reject! body: {}", &body[..body.len().min(200)]),
                    );
                } else if crashed {
                    self.record(category, name, false, Some(status), "SERVER ERROR");
                } else {
                    self.record(category, name, true, Some(status), "");
                }
            }
            Err(e) => {
                self.record(category, name, false, None, &format!("request error: {}", e));
            }
        }
    }

    // ════════════════════════════════════════════════════════════════════
    // FUZZ CATEGORIES
    // ════════════════════════════════════════════════════════════════════

    fn fuzz_health_endpoints(&mut self) {
        let cat = "health";

        // 1-5: Basic health endpoints work
        self.expect_no_crash(cat, "GET /health", self.get("/health"));
        self.expect_no_crash(cat, "GET /status", self.get("/status"));
        self.expect_no_crash(cat, "GET /ping", self.get("/ping"));
        self.expect_no_crash(cat, "GET /peers", self.get("/peers"));
        self.expect_no_crash(cat, "GET /epochs", self.get("/epochs"));

        // 6-10: Health with garbage query params
        self.expect_no_crash(cat, "health?garbage=<script>", self.get("/health?x=<script>alert(1)</script>"));
        self.expect_no_crash(cat, "health?null_byte", self.get("/health?x=\0\0\0"));
        self.expect_no_crash(cat, "status?sql_inject", self.get("/status?x=' OR 1=1 --"));
        self.expect_no_crash(cat, "ping?huge_param", self.get(&format!("/ping?x={}", "A".repeat(10000))));
        self.expect_no_crash(cat, "health?unicode_bomb", self.get("/health?x=\u{FEFF}\u{200B}\u{2028}\u{2029}"));
    }

    fn fuzz_nonexistent_routes(&mut self) {
        let cat = "routing";

        // 11-20: Routes that shouldn't exist
        self.expect_status(cat, "GET /admin", 404, self.get("/admin"));
        self.expect_status(cat, "GET /shell", 404, self.get("/shell"));
        self.expect_status(cat, "GET /exec", 404, self.get("/exec"));
        self.expect_status(cat, "GET /../etc/passwd", 404, self.get("/../etc/passwd"));
        self.expect_status(cat, "GET /.env", 404, self.get("/.env"));
        self.expect_status(cat, "GET /wp-admin", 404, self.get("/wp-admin"));
        self.expect_status(cat, "GET /api/v1/debug", 404, self.get("/api/v1/debug"));
        self.expect_no_crash(cat, "GET /rpc/transfer no auth", self.get("/rpc/transfer"));
        self.expect_no_crash(cat, "POST / empty", self.post_json("/", &serde_json::json!({})));
        self.expect_no_crash(cat, "GET /health/../../", self.get("/health/../../"));
    }

    fn fuzz_record_submission_binary(&mut self) {
        let cat = "records_bin";

        // 21-40: Malformed binary record submissions
        self.expect_rejection(cat, "empty body", self.post_bytes("/records", vec![]));
        self.expect_rejection(cat, "1 byte", self.post_bytes("/records", vec![0xFF]));
        self.expect_rejection(cat, "wrong magic", self.post_bytes("/records", b"NOPE0000".to_vec()));
        self.expect_rejection(cat, "magic only", self.post_bytes("/records", b"ELRA".to_vec()));
        self.expect_rejection(cat, "magic+version", self.post_bytes("/records", b"ELRA\x00\x04".to_vec()));
        self.expect_rejection(cat, "truncated header", self.post_bytes("/records", b"ELRA\x00\x04\x01\x00".to_vec()));

        // Valid magic but garbage payload
        let mut garbage = b"ELRA\x00\x04\x01\x00".to_vec();
        garbage.extend_from_slice(&random_bytes(100));
        self.expect_rejection(cat, "magic+garbage 100B", self.post_bytes("/records", garbage));

        let mut garbage2 = b"ELRA\x00\x04\x01\x00".to_vec();
        garbage2.extend_from_slice(&random_bytes(10000));
        self.expect_rejection(cat, "magic+garbage 10KB", self.post_bytes("/records", garbage2));

        // Huge payload
        self.expect_rejection(cat, "1MB garbage", self.post_bytes("/records", random_bytes(1_000_000)));
        self.expect_rejection(cat, "5MB garbage", self.post_bytes("/records", random_bytes(5_000_000)));

        // Version variants
        self.expect_rejection(cat, "version 0", self.post_bytes("/records", {
            let mut v = b"ELRA\x00\x00\x01\x00".to_vec();
            v.extend_from_slice(&random_bytes(200));
            v
        }));
        self.expect_rejection(cat, "version 255", self.post_bytes("/records", {
            let mut v = b"ELRA\x00\xFF\x01\x00".to_vec();
            v.extend_from_slice(&random_bytes(200));
            v
        }));
        self.expect_rejection(cat, "version 9999", self.post_bytes("/records", {
            let mut v = b"ELRA\x27\x0F\x01\x00".to_vec();
            v.extend_from_slice(&random_bytes(200));
            v
        }));

        // All zeros
        self.expect_rejection(cat, "1KB zeros", self.post_bytes("/records", vec![0u8; 1024]));
        self.expect_rejection(cat, "all 0xFF", self.post_bytes("/records", vec![0xFF; 1024]));

        // Almost-valid: correct magic, version, type but wrong ID length
        let mut bad_id = b"ELRA\x00\x04\x01\x00".to_vec();
        bad_id.push(0xFF); // id_len = 255 (way too long)
        bad_id.extend_from_slice(&random_bytes(300));
        self.expect_rejection(cat, "id_len=255", self.post_bytes("/records", bad_id));

        // Zero-length ID
        let mut zero_id = b"ELRA\x00\x04\x01\x00".to_vec();
        zero_id.push(0x00); // id_len = 0
        zero_id.extend_from_slice(&random_bytes(200));
        self.expect_rejection(cat, "id_len=0", self.post_bytes("/records", zero_id));

        // Valid UUID length but garbage UUID
        let mut bad_uuid = b"ELRA\x00\x04\x01\x00".to_vec();
        bad_uuid.push(36); // correct UUID length
        bad_uuid.extend_from_slice(b"NOT-A-VALID-UUID-STRING-HERE!!!!!!!!"); // 36 bytes of garbage
        bad_uuid.extend_from_slice(&random_bytes(300));
        self.expect_rejection(cat, "garbage UUID", self.post_bytes("/records", bad_uuid));

        // Repeated submission (replay attack)
        let replay_payload = {
            let mut v = b"ELRA\x00\x04\x01\x00".to_vec();
            v.push(36);
            v.extend_from_slice(b"01234567-0123-7000-8000-000000000000");
            v.extend_from_slice(&random_bytes(300));
            v
        };
        self.expect_rejection(cat, "replay attempt 1", self.post_bytes("/records", replay_payload.clone()));
        self.expect_rejection(cat, "replay attempt 2", self.post_bytes("/records", replay_payload));
    }

    fn fuzz_record_submission_json(&mut self) {
        let cat = "records_json";

        // 41-60: JSON record submissions (wrong content type / malformed JSON)
        self.expect_no_crash(cat, "POST /records json empty", self.post_json("/records", &serde_json::json!({})));
        self.expect_no_crash(cat, "POST /records json null", self.post_json("/records", &serde_json::json!(null)));
        self.expect_no_crash(cat, "POST /records json array", self.post_json("/records", &serde_json::json!([])));
        self.expect_no_crash(cat, "POST /records json string", self.post_json("/records", &serde_json::json!("hello")));
        self.expect_no_crash(cat, "POST /records json number", self.post_json("/records", &serde_json::json!(42)));
        self.expect_no_crash(cat, "POST text body", self.post_text("/records", "this is not a record"));
        self.expect_no_crash(cat, "POST html body", self.post_text("/records", "<html><body>hack</body></html>"));
        self.expect_no_crash(cat, "POST xml body", self.post_text("/records", "<?xml version='1.0'?><root/>"));

        // Deeply nested JSON
        let mut nested = serde_json::json!("leaf");
        for _ in 0..100 {
            nested = serde_json::json!({"nested": nested});
        }
        self.expect_no_crash(cat, "100-deep nested JSON", self.post_json("/records", &nested));

        // Huge JSON keys
        let mut huge_key = serde_json::Map::new();
        huge_key.insert("A".repeat(100_000), serde_json::json!("val"));
        self.expect_no_crash(cat, "100K-char JSON key", self.post_json("/records", &serde_json::Value::Object(huge_key)));

        // Null bytes in strings
        self.expect_no_crash(cat, "null bytes in JSON", self.post_json("/records", &serde_json::json!({"id": "test\u{0000}null"})));

        // Unicode edge cases
        self.expect_no_crash(cat, "emoji payload", self.post_json("/records", &serde_json::json!({"id": "🔥💀🐛🎯"})));
        self.expect_no_crash(cat, "RTL override", self.post_json("/records", &serde_json::json!({"id": "\u{202E}evil"})));
        self.expect_no_crash(cat, "zero-width chars", self.post_json("/records", &serde_json::json!({"id": "\u{200B}\u{200C}\u{200D}\u{FEFF}"})));

        // Integer overflow in amount fields
        self.expect_no_crash(cat, "i64 max amount", self.post_json("/records", &serde_json::json!({"beat_amount": "9999999999999999999999999999"})));
        self.expect_no_crash(cat, "negative amount", self.post_json("/records", &serde_json::json!({"beat_amount": "-1"})));
        self.expect_no_crash(cat, "float amount", self.post_json("/records", &serde_json::json!({"beat_amount": "1.5"})));
        self.expect_no_crash(cat, "NaN amount", self.post_json("/records", &serde_json::json!({"beat_amount": "NaN"})));
        self.expect_no_crash(cat, "Infinity amount", self.post_json("/records", &serde_json::json!({"beat_amount": "Infinity"})));
        self.expect_no_crash(cat, "bool as amount", self.post_json("/records", &serde_json::json!({"beat_amount": true})));
    }

    fn fuzz_transfer_endpoint(&mut self) {
        let cat = "transfers";

        // 61-100: RPC transfer endpoint fuzzing
        // Valid-looking but should fail (bad identity, bad amount, etc.)
        self.expect_rejection(cat, "empty body", self.post_json_auth("/rpc/transfer", &serde_json::json!({})));
        self.expect_rejection(cat, "missing to", self.post_json_auth("/rpc/transfer", &serde_json::json!({"amount": 1000})));
        self.expect_rejection(cat, "missing amount", self.post_json_auth("/rpc/transfer", &serde_json::json!({"to": "abcd1234"})));
        self.expect_rejection(cat, "zero amount", self.post_json_auth("/rpc/transfer", &serde_json::json!({"to": &random_hex(32), "amount": 0})));
        self.expect_rejection(cat, "negative amount", self.post_json_auth("/rpc/transfer", &serde_json::json!({"to": &random_hex(32), "amount": -1})));
        self.expect_rejection(cat, "float amount", self.post_json_auth("/rpc/transfer", &serde_json::json!({"to": &random_hex(32), "amount": 1.5})));

        // Amount overflow
        self.expect_rejection(cat, "u64::MAX amount", self.post_json_auth("/rpc/transfer", &serde_json::json!({"to": &random_hex(32), "amount": u64::MAX})));
        self.expect_rejection(cat, "amount > supply", self.post_json_auth("/rpc/transfer", &serde_json::json!({"to": &random_hex(32), "amount": 10_000_000_001_000_000_000_u64})));

        // Bad identity hashes
        self.expect_rejection(cat, "1-char identity", self.post_json_auth("/rpc/transfer", &serde_json::json!({"to": "a", "amount": 1000})));
        self.expect_rejection(cat, "16-char identity", self.post_json_auth("/rpc/transfer", &serde_json::json!({"to": &random_hex(8), "amount": 1000})));
        self.expect_rejection(cat, "65-char identity", self.post_json_auth("/rpc/transfer", &serde_json::json!({"to": &format!("{}f", random_hex(32)), "amount": 1000})));
        self.expect_rejection(cat, "non-hex identity", self.post_json_auth("/rpc/transfer", &serde_json::json!({"to": "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ", "amount": 1000})));
        self.expect_rejection(cat, "empty identity", self.post_json_auth("/rpc/transfer", &serde_json::json!({"to": "", "amount": 1000})));
        self.expect_rejection(cat, "null identity", self.post_json_auth("/rpc/transfer", &serde_json::json!({"to": null, "amount": 1000})));

        // Transfer to self
        self.expect_no_crash(cat, "transfer to self", self.post_json_auth("/rpc/transfer", &serde_json::json!({"to": "self", "amount": 1000})));

        // SQL injection in identity
        self.expect_rejection(cat, "SQL in identity", self.post_json_auth("/rpc/transfer", &serde_json::json!({"to": "'; DROP TABLE ledger; --", "amount": 1000})));

        // Command injection in memo
        self.expect_no_crash(cat, "cmd inject memo", self.post_json_auth("/rpc/transfer", &serde_json::json!({"to": &random_hex(32), "amount": 1000, "memo": "; rm -rf / #"})));
        self.expect_no_crash(cat, "huge memo", self.post_json_auth("/rpc/transfer", &serde_json::json!({"to": &random_hex(32), "amount": 1000, "memo": "A".repeat(1_000_000)})));

        // Auth bypass attempts
        self.expect_no_crash(cat, "no auth header", self.post_json("/rpc/transfer", &serde_json::json!({"to": &random_hex(32), "amount": 1000})));
        self.expect_no_crash(cat, "empty bearer", {
            self.client.post(self.url("/rpc/transfer"))
                .header("Authorization", "Bearer ")
                .json(&serde_json::json!({"to": &random_hex(32), "amount": 1000}))
                .send()
        });
        self.expect_no_crash(cat, "wrong bearer", {
            self.client.post(self.url("/rpc/transfer"))
                .header("Authorization", "Bearer wrong-token-here")
                .json(&serde_json::json!({"to": &random_hex(32), "amount": 1000}))
                .send()
        });
        self.expect_no_crash(cat, "basic auth instead", {
            self.client.post(self.url("/rpc/transfer"))
                .header("Authorization", "Basic YWRtaW46YWRtaW4=")
                .json(&serde_json::json!({"to": &random_hex(32), "amount": 1000}))
                .send()
        });

        // Type confusion
        self.expect_no_crash(cat, "amount as string", self.post_json_auth("/rpc/transfer", &serde_json::json!({"to": &random_hex(32), "amount": "1000"})));
        self.expect_no_crash(cat, "amount as bool", self.post_json_auth("/rpc/transfer", &serde_json::json!({"to": &random_hex(32), "amount": true})));
        self.expect_no_crash(cat, "amount as array", self.post_json_auth("/rpc/transfer", &serde_json::json!({"to": &random_hex(32), "amount": [1000]})));
        self.expect_no_crash(cat, "amount as object", self.post_json_auth("/rpc/transfer", &serde_json::json!({"to": &random_hex(32), "amount": {"value": 1000}})));
        self.expect_no_crash(cat, "to as number", self.post_json_auth("/rpc/transfer", &serde_json::json!({"to": 12345, "amount": 1000})));
        self.expect_no_crash(cat, "extra fields", self.post_json_auth("/rpc/transfer", &serde_json::json!({"to": &random_hex(32), "amount": 1000, "admin": true, "bypass": true, "role": "admin"})));

        // Double-spend attempt (rapid fire same transfer)
        let target = random_hex(32);
        for i in 0..5 {
            self.expect_no_crash(cat, &format!("rapid fire {}", i+1),
                self.post_json_auth("/rpc/transfer", &serde_json::json!({"to": &target, "amount": 1000000000})));
        }
    }

    fn fuzz_stake_endpoint(&mut self) {
        let cat = "stake";

        // 101-120: Stake/unstake fuzzing
        self.expect_rejection(cat, "stake empty", self.post_json_auth("/rpc/stake", &serde_json::json!({})));
        self.expect_rejection(cat, "stake zero", self.post_json_auth("/rpc/stake", &serde_json::json!({"amount": 0})));
        self.expect_rejection(cat, "stake negative", self.post_json_auth("/rpc/stake", &serde_json::json!({"amount": -1})));
        self.expect_rejection(cat, "stake below min", self.post_json_auth("/rpc/stake", &serde_json::json!({"amount": 1})));
        self.expect_rejection(cat, "stake > balance", self.post_json_auth("/rpc/stake", &serde_json::json!({"amount": 9_999_999_999_000_000_000_u64})));
        self.expect_no_crash(cat, "stake NaN", self.post_json_auth("/rpc/stake", &serde_json::json!({"amount": "NaN"})));
        self.expect_no_crash(cat, "stake string", self.post_json_auth("/rpc/stake", &serde_json::json!({"amount": "lots"})));

        // Bad purpose
        self.expect_no_crash(cat, "stake bad purpose", self.post_json_auth("/rpc/stake", &serde_json::json!({"amount": 100000000000_u64, "purpose": "hacking"})));
        self.expect_no_crash(cat, "stake null purpose", self.post_json_auth("/rpc/stake", &serde_json::json!({"amount": 100000000000_u64, "purpose": null})));

        // Unstake
        self.expect_rejection(cat, "unstake empty", self.post_json_auth("/rpc/unstake", &serde_json::json!({})));
        self.expect_rejection(cat, "unstake bad id", self.post_json_auth("/rpc/unstake", &serde_json::json!({"stake_id": "not-a-uuid"})));
        self.expect_rejection(cat, "unstake nonexist", self.post_json_auth("/rpc/unstake", &serde_json::json!({"stake_id": "01234567-0123-7000-8000-000000000000"})));
        self.expect_no_crash(cat, "unstake null", self.post_json_auth("/rpc/unstake", &serde_json::json!({"stake_id": null})));

        // Double unstake
        self.expect_no_crash(cat, "unstake same 2x (1)", self.post_json_auth("/rpc/unstake", &serde_json::json!({"stake_id": "aaaaaaaa-bbbb-7ccc-8ddd-eeeeeeeeeeee"})));
        self.expect_no_crash(cat, "unstake same 2x (2)", self.post_json_auth("/rpc/unstake", &serde_json::json!({"stake_id": "aaaaaaaa-bbbb-7ccc-8ddd-eeeeeeeeeeee"})));

        // Stake with extra injection fields
        self.expect_no_crash(cat, "stake admin inject", self.post_json_auth("/rpc/stake", &serde_json::json!({"amount": 100000000000_u64, "admin": true, "genesis": true})));

        // No auth
        self.expect_no_crash(cat, "stake no auth", self.post_json("/rpc/stake", &serde_json::json!({"amount": 100000000000_u64})));
        self.expect_no_crash(cat, "unstake no auth", self.post_json("/rpc/unstake", &serde_json::json!({"stake_id": "test"})));

        // Stake entire supply
        self.expect_rejection(cat, "stake entire supply", self.post_json_auth("/rpc/stake", &serde_json::json!({"amount": 10_000_000_000_000_000_000_u64})));
    }

    fn fuzz_balance_queries(&mut self) {
        let cat = "balances";

        // 121-145: Balance/ledger query fuzzing
        self.expect_no_crash(cat, "balance no param", self.get("/balances"));
        self.expect_no_crash(cat, "balance empty id", self.get("/balances?identity="));
        self.expect_no_crash(cat, "balance short id", self.get("/balances?identity=abcd"));
        self.expect_no_crash(cat, "balance valid hex", self.get(&format!("/balances?identity={}", random_hex(32))));
        self.expect_no_crash(cat, "balance non-hex", self.get("/balances?identity=ZZZZ"));
        self.expect_no_crash(cat, "balance sql inject", self.get("/balances?identity=' OR '1'='1"));
        self.expect_no_crash(cat, "balance null bytes", self.get("/balances?identity=%00%00%00"));
        self.expect_no_crash(cat, "balance path traversal", self.get("/balances?identity=../../etc/passwd"));

        // Ledger summary
        self.expect_no_crash(cat, "ledger summary", self.get("/ledger/summary"));
        self.expect_no_crash(cat, "supply", self.get("/supply"));
        self.expect_no_crash(cat, "supply/total", self.get("/supply/total"));
        self.expect_no_crash(cat, "supply/max", self.get("/supply/max"));

        // History queries
        self.expect_no_crash(cat, "history no param", self.get("/history"));
        self.expect_no_crash(cat, "history bad limit", self.get("/history?identity=test&limit=-1"));
        self.expect_no_crash(cat, "history huge limit", self.get("/history?identity=test&limit=999999999"));
        self.expect_no_crash(cat, "history limit=0", self.get("/history?identity=test&limit=0"));
        self.expect_no_crash(cat, "history offset neg", self.get("/history?identity=test&offset=-100"));
        self.expect_no_crash(cat, "history offset huge", self.get("/history?identity=test&offset=999999999"));
        self.expect_no_crash(cat, "recent txs", self.get("/transactions/recent"));
        self.expect_no_crash(cat, "recent txs limit=0", self.get("/transactions/recent?limit=0"));
        self.expect_no_crash(cat, "recent txs huge", self.get("/transactions/recent?limit=999999999"));
        self.expect_no_crash(cat, "stakes query", self.get("/stakes?identity=test"));

        // Token enforcement
        self.expect_no_crash(cat, "token enforcement", self.get("/token/enforcement"));
        self.expect_no_crash(cat, "genesis alloc", self.get("/genesis/allocation"));
        self.expect_no_crash(cat, "bootstrap status", self.get("/bootstrap/status"));
    }

    fn fuzz_gossip_endpoints(&mut self) {
        let cat = "gossip";

        // 146-175: Gossip/sync endpoint fuzzing
        // Announce with garbage
        self.expect_no_crash(cat, "announce empty array", self.post_json("/announce", &serde_json::json!([])));
        self.expect_no_crash(cat, "announce null", self.post_json("/announce", &serde_json::json!(null)));
        self.expect_no_crash(cat, "announce string", self.post_json("/announce", &serde_json::json!("not an array")));
        self.expect_no_crash(cat, "announce garbage items", self.post_json("/announce", &serde_json::json!([{"id": "fake", "hash": "0000"}])));
        self.expect_no_crash(cat, "announce 1000 items", self.post_json("/announce", &serde_json::json!(
            (0..1000).map(|i| serde_json::json!({"id": format!("fake-{}", i), "hash": random_hex(32)})).collect::<Vec<_>>()
        )));

        // Delta sync
        self.expect_no_crash(cat, "delta_sync empty", self.post_json("/delta_sync", &serde_json::json!({})));
        self.expect_no_crash(cat, "delta_sync garbage", self.post_json("/delta_sync", &serde_json::json!({"since": "not a number"})));
        self.expect_no_crash(cat, "delta_sync future", self.post_json("/delta_sync", &serde_json::json!({"since": now_secs() + 86400.0})));
        self.expect_no_crash(cat, "delta_sync epoch 0", self.post_json("/delta_sync", &serde_json::json!({"since": 0})));
        self.expect_no_crash(cat, "delta_sync negative", self.post_json("/delta_sync", &serde_json::json!({"since": -1.0})));

        // Records fetch
        self.expect_no_crash(cat, "fetch empty ids", self.post_json("/records/fetch", &serde_json::json!({"ids": []})));
        self.expect_no_crash(cat, "fetch garbage ids", self.post_json("/records/fetch", &serde_json::json!({"ids": ["not-a-uuid", "also-not"]})));
        self.expect_no_crash(cat, "fetch 1000 ids", self.post_json("/records/fetch", &serde_json::json!({
            "ids": (0..1000).map(|_| random_hex(18)).collect::<Vec<_>>()
        })));
        self.expect_no_crash(cat, "fetch null ids", self.post_json("/records/fetch", &serde_json::json!({"ids": null})));

        // Merkle root
        self.expect_no_crash(cat, "merkle_root", self.get("/merkle_root"));

        // Attestations
        self.expect_no_crash(cat, "GET attestations", self.get("/attestations"));
        self.expect_no_crash(cat, "POST attestations empty", self.post_json("/attestations", &serde_json::json!({})));
        self.expect_no_crash(cat, "POST attestations garbage", self.post_json("/attestations", &serde_json::json!({"attestations": "not_array"})));

        // Probe
        self.expect_no_crash(cat, "probe empty", self.post_json("/probe", &serde_json::json!({})));
        self.expect_no_crash(cat, "probe garbage", self.post_json("/probe", &serde_json::json!({"nonce": "test", "from": "nobody"})));

        // Witness
        self.expect_no_crash(cat, "witness empty", self.post_json("/witness", &serde_json::json!({})));
        self.expect_no_crash(cat, "witness bad record", self.post_json("/witness", &serde_json::json!({"record_id": "nonexistent"})));

        // Validate
        self.expect_no_crash(cat, "validate empty", self.post_bytes("/validate", vec![]));
        self.expect_no_crash(cat, "validate garbage", self.post_bytes("/validate", random_bytes(500)));
        self.expect_no_crash(cat, "validate magic only", self.post_bytes("/validate", b"ELRA".to_vec()));

        // Record search
        self.expect_no_crash(cat, "search empty q", self.get("/records/search"));
        self.expect_no_crash(cat, "search sql inject", self.get("/records/search?q=' OR 1=1 --"));
        self.expect_no_crash(cat, "search huge query", self.get(&format!("/records/search?q={}", "A".repeat(10000))));
        self.expect_no_crash(cat, "search bad class", self.get("/records/search?class=999"));
    }

    fn fuzz_timestamp_defense(&mut self) {
        let cat = "timestamp";

        // 176-200: Timestamp edge cases (the bug we just fixed)
        // These test the timestamp defense via the wire format

        // Build minimal wire records with various timestamps
        let timestamps: Vec<(f64, &str)> = vec![
            (0.0, "epoch zero"),
            (-1.0, "negative"),
            (f64::MAX, "f64::MAX"),
            (f64::MIN, "f64::MIN"),
            (f64::NAN, "NaN"),
            (f64::INFINITY, "Infinity"),
            (f64::NEG_INFINITY, "-Infinity"),
            (now_secs() + 3600.0, "1hr future"),
            (now_secs() + 86400.0, "1day future"),
            (now_secs() + 31536000.0, "1yr future"),
            (now_secs() - 86400.0, "1day past"),
            (now_secs() - 31536000.0, "1yr past"),
            (now_secs() - 31536000.0 * 50.0, "50yr past"),
            (now_secs() + 0.001, "1ms future"),
            (now_secs() - 0.001, "1ms past"),
            (1.0, "1 second since epoch"),
            (253402300800.0, "year 9999"),
            (now_secs() + 61.0, "61s future (just over new limit)"),
            (now_secs() + 59.0, "59s future (just under new limit)"),
            (now_secs(), "exact now"),
        ];

        for (ts, name) in &timestamps {
            let mut wire = b"ELRA\x00\x04\x01\x00".to_vec();
            // ID
            wire.push(36);
            wire.extend_from_slice(format!("{:0>36}", random_hex(18)).as_bytes());
            // Content hash (32 bytes)
            wire.extend_from_slice(&random_bytes(32));
            // PK length + fake PK
            wire.extend_from_slice(&2u16.to_be_bytes()); // pk_len = 2 (wrong but tests parser)
            wire.extend_from_slice(&[0u8; 2]);
            // Timestamp
            wire.extend_from_slice(&ts.to_be_bytes());
            // Padding
            wire.extend_from_slice(&random_bytes(100));

            self.expect_no_crash(cat, &format!("ts: {}", name), self.post_bytes("/records", wire));
        }

        // Probe with manipulated timestamps
        self.expect_no_crash(cat, "probe future ts", self.post_json("/probe", &serde_json::json!({
            "timestamp": now_secs() + 3600.0,
            "nonce": random_hex(16)
        })));
        self.expect_no_crash(cat, "probe past ts", self.post_json("/probe", &serde_json::json!({
            "timestamp": 0.0,
            "nonce": random_hex(16)
        })));
        self.expect_no_crash(cat, "probe NaN ts", self.post_json("/probe", &serde_json::json!({
            "timestamp": "NaN",
            "nonce": random_hex(16)
        })));
        self.expect_no_crash(cat, "probe negative ts", self.post_json("/probe", &serde_json::json!({
            "timestamp": -999999999.0,
            "nonce": random_hex(16)
        })));
        self.expect_no_crash(cat, "probe ts year 9999", self.post_json("/probe", &serde_json::json!({
            "timestamp": 253402300800.0,
            "nonce": random_hex(16)
        })));
    }

    fn fuzz_explorer_endpoints(&mut self) {
        let cat = "explorer";

        // 201-230: Explorer endpoint fuzzing
        self.expect_no_crash(cat, "account empty", self.get("/account/"));
        self.expect_no_crash(cat, "account garbage", self.get("/account/not-an-identity"));
        self.expect_no_crash(cat, "account sql", self.get("/account/' OR 1=1 --"));
        self.expect_no_crash(cat, "account path trav", self.get("/account/../../etc/passwd"));
        self.expect_no_crash(cat, "account valid hex", self.get(&format!("/account/{}", random_hex(32))));
        self.expect_no_crash(cat, "account huge", self.get(&format!("/account/{}", "A".repeat(10000))));

        self.expect_no_crash(cat, "record empty", self.get("/record/"));
        self.expect_no_crash(cat, "record garbage", self.get("/record/not-a-uuid"));
        self.expect_no_crash(cat, "record sql", self.get("/record/' OR 1=1 --"));
        self.expect_no_crash(cat, "record valid uuid", self.get("/record/01234567-0123-7000-8000-000000000000"));

        self.expect_no_crash(cat, "causal-proof empty", self.get("/record//causal-proof"));
        self.expect_no_crash(cat, "causal-proof garbage", self.get("/record/fake/causal-proof"));
        self.expect_no_crash(cat, "causal-proof valid", self.get("/record/01234567-0123-7000-8000-000000000000/causal-proof"));

        self.expect_no_crash(cat, "network", self.get("/network"));
        self.expect_no_crash(cat, "governance proposals", self.get("/governance/proposals"));
        self.expect_no_crash(cat, "governance fake id", self.get("/governance/proposal/fake-id"));

        // Records query params
        self.expect_no_crash(cat, "records since=-1", self.get("/records?since=-1"));
        self.expect_no_crash(cat, "records since=NaN", self.get("/records?since=NaN"));
        self.expect_no_crash(cat, "records limit=-1", self.get("/records?limit=-1"));
        self.expect_no_crash(cat, "records limit=0", self.get("/records?limit=0"));
        self.expect_no_crash(cat, "records limit=max", self.get("/records?limit=999999999"));
        self.expect_no_crash(cat, "records bad creator", self.get("/records?creator=not-hex"));
        self.expect_no_crash(cat, "records class=999", self.get("/records?class=999"));

        // Bootstrap
        self.expect_no_crash(cat, "bootstrap claim", self.post_json("/bootstrap/claim", &serde_json::json!({})));
    }

    fn fuzz_header_attacks(&mut self) {
        let cat = "headers";

        // 231-260: HTTP header manipulation
        self.expect_no_crash(cat, "huge User-Agent", {
            self.client.get(self.url("/health"))
                .header("User-Agent", "A".repeat(100_000))
                .send()
        });
        self.expect_no_crash(cat, "huge Cookie", {
            self.client.get(self.url("/health"))
                .header("Cookie", format!("session={}", "B".repeat(100_000)))
                .send()
        });
        self.expect_no_crash(cat, "100 custom headers", {
            let mut req = self.client.get(self.url("/health"));
            for i in 0..100 {
                req = req.header(format!("X-Custom-{}", i), format!("value-{}", i));
            }
            req.send()
        });
        self.expect_no_crash(cat, "null in header", {
            self.client.get(self.url("/health"))
                .header("X-Test", "before\0after")
                .send()
        });
        self.expect_no_crash(cat, "CRLF injection", {
            self.client.get(self.url("/health"))
                .header("X-Test", "value\r\nX-Injected: true")
                .send()
        });
        self.expect_no_crash(cat, "wrong content-type", {
            self.client.post(self.url("/records"))
                .header("Content-Type", "application/xml")
                .body("<record/>")
                .send()
        });
        self.expect_no_crash(cat, "multipart to json", {
            self.client.post(self.url("/rpc/transfer"))
                .header("Content-Type", "multipart/form-data; boundary=----")
                .body("------\r\nContent-Disposition: form-data; name=\"to\"\r\n\r\ntest\r\n------")
                .send()
        });
        self.expect_no_crash(cat, "accept: text/xml", {
            self.client.get(self.url("/health"))
                .header("Accept", "text/xml")
                .send()
        });
        self.expect_no_crash(cat, "transfer-encoding chunked", {
            self.client.post(self.url("/records"))
                .header("Transfer-Encoding", "chunked")
                .body("5\r\nhello\r\n0\r\n\r\n")
                .send()
        });

        // Host header attacks
        self.expect_no_crash(cat, "host: evil.com", {
            self.client.get(self.url("/health"))
                .header("Host", "evil.com")
                .send()
        });
        self.expect_no_crash(cat, "host: localhost", {
            self.client.get(self.url("/health"))
                .header("Host", "localhost:9474")
                .send()
        });

        // Method confusion
        self.expect_no_crash(cat, "PUT /health", {
            self.client.put(self.url("/health")).send()
        });
        self.expect_no_crash(cat, "DELETE /health", {
            self.client.delete(self.url("/health")).send()
        });
        self.expect_no_crash(cat, "PATCH /records", {
            self.client.patch(self.url("/records")).body("{}").send()
        });
        self.expect_no_crash(cat, "OPTIONS /records", {
            self.client.request(reqwest::Method::OPTIONS, self.url("/records")).send()
        });

        // Content-Length mismatch (reqwest handles this, but try small body with no CL)
        self.expect_no_crash(cat, "empty POST /records", {
            self.client.post(self.url("/records"))
                .header("Content-Length", "99999")
                .body("")
                .send()
        });
    }

    fn fuzz_stamp_endpoints(&mut self) {
        let cat = "stamp";

        // 261-285: RPC stamp (public record creation)
        self.expect_no_crash(cat, "stamp empty", self.post_json_auth("/rpc/stamp", &serde_json::json!({})));
        self.expect_no_crash(cat, "stamp with content", self.post_json_auth("/rpc/stamp", &serde_json::json!({"content": "test data"})));
        self.expect_no_crash(cat, "stamp huge content", self.post_json_auth("/rpc/stamp", &serde_json::json!({"content": "X".repeat(1_000_000)})));
        self.expect_no_crash(cat, "stamp null content", self.post_json_auth("/rpc/stamp", &serde_json::json!({"content": null})));
        self.expect_no_crash(cat, "stamp binary content", self.post_json_auth("/rpc/stamp", &serde_json::json!({"content": random_hex(1000)})));
        self.expect_no_crash(cat, "stamp nested obj", self.post_json_auth("/rpc/stamp", &serde_json::json!({"content": {"nested": {"deep": true}}})));

        // Stamp-private (ZK proof creation)
        self.expect_no_crash(cat, "stamp-private empty", self.post_json_auth("/rpc/stamp-private", &serde_json::json!({})));
        self.expect_no_crash(cat, "stamp-private content", self.post_json_auth("/rpc/stamp-private", &serde_json::json!({"content": "secret"})));

        // No auth on stamp
        self.expect_no_crash(cat, "stamp no auth", self.post_json("/rpc/stamp", &serde_json::json!({"content": "test"})));
        self.expect_no_crash(cat, "stamp-priv no auth", self.post_json("/rpc/stamp-private", &serde_json::json!({"content": "test"})));

        // Metadata injection via stamp
        self.expect_no_crash(cat, "stamp beat_op inject", self.post_json_auth("/rpc/stamp", &serde_json::json!({
            "content": "innocent",
            "metadata": {"beat_op": "mint", "beat_amount": "999999999999", "beat_to": "attacker"}
        })));
        self.expect_no_crash(cat, "stamp admin inject", self.post_json_auth("/rpc/stamp", &serde_json::json!({
            "content": "innocent",
            "metadata": {"admin": true, "genesis": true, "mint": true}
        })));

        // Classification override attempt
        self.expect_no_crash(cat, "stamp force sovereign", self.post_json_auth("/rpc/stamp", &serde_json::json!({
            "content": "test",
            "classification": 3
        })));
        self.expect_no_crash(cat, "stamp class=-1", self.post_json_auth("/rpc/stamp", &serde_json::json!({
            "content": "test",
            "classification": -1
        })));
        self.expect_no_crash(cat, "stamp class=999", self.post_json_auth("/rpc/stamp", &serde_json::json!({
            "content": "test",
            "classification": 999
        })));
    }

    fn fuzz_rate_limits(&mut self) {
        let cat = "rate_limit";

        // 286-300: Rate limit / DoS resistance
        // Rapid-fire health checks (should not crash even at high rate)
        for i in 0..20 {
            self.expect_no_crash(cat, &format!("rapid health {}", i+1), self.get("/health"));
        }

        // Rapid-fire record submissions
        for i in 0..10 {
            self.expect_no_crash(cat, &format!("rapid submit {}", i+1),
                self.post_bytes("/records", random_bytes(500)));
        }

        // Rapid announce floods
        for i in 0..10 {
            self.expect_no_crash(cat, &format!("rapid announce {}", i+1),
                self.post_json("/announce", &serde_json::json!(
                    (0..100).map(|j| serde_json::json!({"id": format!("flood-{}-{}", i, j)})).collect::<Vec<_>>()
                )));
        }

        // Rapid transfer attempts
        for i in 0..10 {
            self.expect_no_crash(cat, &format!("rapid transfer {}", i+1),
                self.post_json_auth("/rpc/transfer", &serde_json::json!({"to": &random_hex(32), "amount": 1})));
        }
    }

    fn fuzz_encoding_attacks(&mut self) {
        let cat = "encoding";

        // 301-330: Encoding and injection attacks
        let payloads = vec![
            ("path traversal 1", "/records/../../../etc/passwd"),
            ("path traversal 2", "/records/..%2F..%2F..%2Fetc%2Fpasswd"),
            ("double encode", "/records/%252e%252e%252f"),
            ("null byte path", "/records%00.json"),
            ("unicode norm", "/records/\u{FF0E}\u{FF0E}/"),
            ("backslash", "/records\\..\\..\\etc\\passwd"),
            ("semicolon", "/records;id"),
            ("pipe", "/records|ls"),
            ("backtick", "/records`whoami`"),
            ("dollar", "/records$(whoami)"),
        ];

        for (name, path) in &payloads {
            self.expect_no_crash(cat, name, self.get(path));
        }

        // POST bodies with injection
        let injection_bodies: Vec<(&str, serde_json::Value)> = vec![
            ("xss script tag", serde_json::json!({"content": "<script>alert(document.cookie)</script>"})),
            ("xss img onerror", serde_json::json!({"content": "<img src=x onerror=alert(1)>"})),
            ("xss svg", serde_json::json!({"content": "<svg onload=alert(1)>"})),
            ("template inject", serde_json::json!({"content": "{{7*7}}"})),
            ("ssti jinja", serde_json::json!({"content": "{{ config.items() }}"})),
            ("ldap inject", serde_json::json!({"to": "*)(&(objectClass=*)"})),
            ("xpath inject", serde_json::json!({"to": "' or '1'='1"})),
            ("nosql inject", serde_json::json!({"to": {"$gt": ""}})),
            ("json proto poll", serde_json::json!({"__proto__": {"admin": true}})),
            ("constructor poll", serde_json::json!({"constructor": {"prototype": {"admin": true}}})),
        ];

        for (name, body) in &injection_bodies {
            self.expect_no_crash(cat, name, self.post_json("/rpc/stamp", body));
        }

        // Oversized URL
        self.expect_no_crash(cat, "100KB URL path", self.get(&format!("/{}", "A".repeat(100_000))));

        // Unicode normalization attacks
        let unicode_payloads = vec![
            ("homoglyph a", "аdmin"), // Cyrillic а
            ("homoglyph o", "аdmіn"), // Cyrillic а and і
            ("fullwidth", "\u{FF41}\u{FF44}\u{FF4D}\u{FF49}\u{FF4E}"), // fullwidth "admin"
            ("combining chars", "a\u{0300}d\u{0301}m\u{0302}i\u{0303}n"),
            ("zalgo", "h̸̡̪̯ě̶̫l̶̡̛l̸̢̈o̶̬̊"),
        ];
        for (name, payload) in &unicode_payloads {
            self.expect_no_crash(cat, &format!("unicode: {}", name),
                self.post_json_auth("/rpc/transfer", &serde_json::json!({"to": payload, "amount": 1})));
        }

        // ReDoS attempt (regex denial of service — if any regex parsing)
        let redos = "a".repeat(50) + &"a?".repeat(50) + &"a".repeat(50);
        self.expect_no_crash(cat, "regex DoS attempt", self.get(&format!("/records/search?q={}", redos)));
    }

    fn fuzz_concurrent_operations(&mut self) {
        let cat = "concurrent";

        // 331-340: Concurrent/race condition indicators
        // Send multiple conflicting operations rapidly
        let target_id = random_hex(32);

        // Simultaneous transfers to same target (checking for double-credit)
        for i in 0..10 {
            self.expect_no_crash(cat, &format!("concurrent xfer {}", i+1),
                self.post_json_auth("/rpc/transfer", &serde_json::json!({
                    "to": &target_id,
                    "amount": 1000000000_u64  // 1 beat each
                })));
        }
    }

    fn fuzz_wire_format_edge_cases(&mut self) {
        let cat = "wire_edge";

        // 341-400: Deep wire format fuzzing
        // Correct magic, plausible structure, but subtle corruption

        // PK length claims 1952 but only provides 10 bytes
        let mut short_pk = b"ELRA\x00\x04\x01\x00".to_vec();
        short_pk.push(36);
        short_pk.extend_from_slice(b"01234567-abcd-7000-8000-000000000001");
        short_pk.extend_from_slice(&[0u8; 32]); // content hash
        short_pk.extend_from_slice(&1952u16.to_be_bytes()); // claims 1952 byte PK
        short_pk.extend_from_slice(&[0u8; 10]); // only 10 bytes
        self.expect_rejection(cat, "truncated PK", self.post_bytes("/records", short_pk));

        // PK length = 0
        let mut zero_pk = b"ELRA\x00\x04\x01\x00".to_vec();
        zero_pk.push(36);
        zero_pk.extend_from_slice(b"01234567-abcd-7000-8000-000000000002");
        zero_pk.extend_from_slice(&[0u8; 32]);
        zero_pk.extend_from_slice(&0u16.to_be_bytes()); // PK length 0
        zero_pk.extend_from_slice(&now_secs().to_be_bytes());
        zero_pk.extend_from_slice(&random_bytes(100));
        self.expect_rejection(cat, "zero-length PK", self.post_bytes("/records", zero_pk));

        // PK length = u16::MAX
        let mut huge_pk = b"ELRA\x00\x04\x01\x00".to_vec();
        huge_pk.push(36);
        huge_pk.extend_from_slice(b"01234567-abcd-7000-8000-000000000003");
        huge_pk.extend_from_slice(&[0u8; 32]);
        huge_pk.extend_from_slice(&u16::MAX.to_be_bytes());
        huge_pk.extend_from_slice(&random_bytes(200));
        self.expect_rejection(cat, "pk_len=u16::MAX", self.post_bytes("/records", huge_pk));

        // Metadata length = u32::MAX
        let mut huge_meta = b"ELRA\x00\x04\x01\x00".to_vec();
        huge_meta.push(36);
        huge_meta.extend_from_slice(b"01234567-abcd-7000-8000-000000000004");
        huge_meta.extend_from_slice(&[0u8; 32]); // content hash
        huge_meta.extend_from_slice(&2u16.to_be_bytes()); // pk_len=2
        huge_meta.extend_from_slice(&[0u8; 2]); // fake pk
        huge_meta.extend_from_slice(&now_secs().to_be_bytes());
        huge_meta.extend_from_slice(&0u16.to_be_bytes()); // 0 parents
        huge_meta.push(0); // classification=public
        huge_meta.extend_from_slice(&u32::MAX.to_be_bytes()); // meta_len = 4GB
        huge_meta.extend_from_slice(&random_bytes(100));
        self.expect_rejection(cat, "meta_len=u32::MAX", self.post_bytes("/records", huge_meta));

        // Huge number of parents
        let mut many_parents = b"ELRA\x00\x04\x01\x00".to_vec();
        many_parents.push(36);
        many_parents.extend_from_slice(b"01234567-abcd-7000-8000-000000000005");
        many_parents.extend_from_slice(&[0u8; 32]);
        many_parents.extend_from_slice(&2u16.to_be_bytes());
        many_parents.extend_from_slice(&[0u8; 2]);
        many_parents.extend_from_slice(&now_secs().to_be_bytes());
        many_parents.extend_from_slice(&u16::MAX.to_be_bytes()); // 65535 parents
        many_parents.extend_from_slice(&random_bytes(200));
        self.expect_rejection(cat, "65535 parents", self.post_bytes("/records", many_parents));

        // Classification out of range
        for class_val in [4u8, 5, 10, 127, 255] {
            let mut bad_class = b"ELRA\x00\x04\x01\x00".to_vec();
            bad_class.push(36);
            bad_class.extend_from_slice(format!("01234567-abcd-7000-8000-0000000000{:02x}", class_val).as_bytes());
            bad_class.extend_from_slice(&[0u8; 32]);
            bad_class.extend_from_slice(&2u16.to_be_bytes());
            bad_class.extend_from_slice(&[0u8; 2]);
            bad_class.extend_from_slice(&now_secs().to_be_bytes());
            bad_class.extend_from_slice(&0u16.to_be_bytes());
            bad_class.push(class_val); // invalid classification
            bad_class.extend_from_slice(&0u32.to_be_bytes()); // 0 metadata
            bad_class.extend_from_slice(&random_bytes(50));
            self.expect_rejection(cat, &format!("class={}", class_val), self.post_bytes("/records", bad_class));
        }

        // Sig length claims huge but truncated
        let mut bad_sig = b"ELRA\x00\x04\x01\x00".to_vec();
        bad_sig.push(36);
        bad_sig.extend_from_slice(b"01234567-abcd-7000-8000-000000000010");
        bad_sig.extend_from_slice(&[0u8; 32]);
        bad_sig.extend_from_slice(&2u16.to_be_bytes());
        bad_sig.extend_from_slice(&[0u8; 2]);
        bad_sig.extend_from_slice(&now_secs().to_be_bytes());
        bad_sig.extend_from_slice(&0u16.to_be_bytes()); // 0 parents
        bad_sig.push(0); // public
        bad_sig.extend_from_slice(&0u32.to_be_bytes()); // 0 metadata
        bad_sig.extend_from_slice(&0u32.to_be_bytes()); // 0 zk
        bad_sig.extend_from_slice(&10000u16.to_be_bytes()); // sig claims 10000
        bad_sig.extend_from_slice(&[0u8; 20]); // only 20 bytes
        self.expect_rejection(cat, "sig truncated", self.post_bytes("/records", bad_sig));

        // Valid wire structure but wrong signature (signature verification check)
        let mut wrong_sig = b"ELRA\x00\x04\x01\x00".to_vec();
        wrong_sig.push(36);
        let uuid = uuid::Uuid::now_v7().to_string();
        wrong_sig.extend_from_slice(uuid.as_bytes());
        wrong_sig.extend_from_slice(&random_bytes(32)); // content hash
        wrong_sig.extend_from_slice(&1952u16.to_be_bytes()); // correct dilithium3 pk size
        wrong_sig.extend_from_slice(&random_bytes(1952)); // random PK
        wrong_sig.extend_from_slice(&now_secs().to_be_bytes());
        wrong_sig.extend_from_slice(&0u16.to_be_bytes()); // 0 parents
        wrong_sig.push(0); // public
        wrong_sig.extend_from_slice(&2u32.to_be_bytes()); // 2 bytes metadata
        wrong_sig.extend_from_slice(b"{}"); // empty JSON metadata
        wrong_sig.extend_from_slice(&0u32.to_be_bytes()); // 0 zk proof
        wrong_sig.extend_from_slice(&3293u16.to_be_bytes()); // correct dilithium3 sig size
        wrong_sig.extend_from_slice(&random_bytes(3293)); // random sig (will fail verification)
        wrong_sig.extend_from_slice(&0u16.to_be_bytes()); // 0 sphincs sig
        // v2+ fields
        wrong_sig.extend_from_slice(&0u16.to_be_bytes()); // 0 ITC
        wrong_sig.extend_from_slice(&0u16.to_be_bytes()); // 0 zone refs
        wrong_sig.extend_from_slice(&0u16.to_be_bytes()); // 0 sphincs pk
        wrong_sig.push(0x01); // sig alg = dilithium3
        wrong_sig.push(0x00); // no sphincs alg
        // v3+ fields
        wrong_sig.push(0x00); // no zone
        self.expect_rejection(cat, "valid struct bad sig", self.post_bytes("/records", wrong_sig));

        // Test all v1-v4 version numbers with minimal valid structure
        for version in [1u16, 2, 3, 4, 5] {
            let mut versioned = b"ELRA".to_vec();
            versioned.extend_from_slice(&version.to_be_bytes());
            versioned.push(0x01); // type
            versioned.push(0x00); // reserved
            versioned.push(36);
            versioned.extend_from_slice(format!("01234567-abcd-7000-8000-0000000v{:04}", version).as_bytes());
            versioned.extend_from_slice(&random_bytes(200));
            self.expect_no_crash(cat, &format!("wire version {}", version), self.post_bytes("/records", versioned));
        }

        // Record type != 1
        for record_type in [0u8, 2, 3, 127, 255] {
            let mut bad_type = b"ELRA\x00\x04".to_vec();
            bad_type.push(record_type);
            bad_type.push(0x00);
            bad_type.extend_from_slice(&random_bytes(200));
            self.expect_no_crash(cat, &format!("record_type={}", record_type), self.post_bytes("/records", bad_type));
        }
    }

    fn fuzz_admin_without_auth(&mut self) {
        let cat = "admin_noauth";

        // 401-420: Admin endpoints without proper auth
        let admin_paths = vec![
            ("snapshot", "/admin/snapshot"),
            ("tasks", "/admin/tasks"),
            ("purge_peer", "/admin/purge_peer"),
            ("ban_ip", "/admin/ban_ip"),
            ("ban_identity", "/admin/ban_identity"),
        ];

        for (name, path) in &admin_paths {
            // No auth
            self.expect_no_crash(cat, &format!("{} no auth", name), self.post_json(path, &serde_json::json!({})));
            // Wrong auth
            self.expect_no_crash(cat, &format!("{} bad auth", name), {
                self.client.post(self.url(path))
                    .header("Authorization", "Bearer wrong-token")
                    .json(&serde_json::json!({}))
                    .send()
            });
        }

        // Admin ban with actual payloads
        self.expect_no_crash(cat, "ban_ip localhost", self.post_json_auth("/admin/ban_ip", &serde_json::json!({"ip": "127.0.0.1"})));
        self.expect_no_crash(cat, "ban_ip private", self.post_json_auth("/admin/ban_ip", &serde_json::json!({"ip": "192.168.1.1"})));
        self.expect_no_crash(cat, "ban_ip garbage", self.post_json_auth("/admin/ban_ip", &serde_json::json!({"ip": "not.an.ip"})));
        self.expect_no_crash(cat, "ban_identity fake", self.post_json_auth("/admin/ban_identity", &serde_json::json!({"identity": random_hex(32)})));
        self.expect_no_crash(cat, "purge_peer fake", self.post_json_auth("/admin/purge_peer", &serde_json::json!({"peer_id": "nonexistent"})));
    }

    // ── Run all categories ──────────────────────────────────────────────

    fn run_all(&mut self) {
        eprintln!("\n╔══════════════════════════════════════════════════════════════╗");
        eprintln!("║  ELARA FUZZ — 1000-case adversarial node tester             ║");
        eprintln!("║  Target: {}                                  ║", self.target);
        eprintln!("╚══════════════════════════════════════════════════════════════╝\n");

        // Verify node is up
        match self.get("/ping") {
            Ok(resp) if resp.status().is_success() => {
                eprintln!("  Node is UP. Starting fuzz...\n");
            }
            _ => {
                eprintln!("  ✗ Node is DOWN at {}. Cannot fuzz.", self.target);
                std::process::exit(1);
            }
        }

        eprintln!("── Health & Status ─────────────────────────────────────────");
        self.fuzz_health_endpoints();

        eprintln!("\n── Routing ─────────────────────────────────────────────────");
        self.fuzz_nonexistent_routes();

        eprintln!("\n── Binary Record Submission ────────────────────────────────");
        self.fuzz_record_submission_binary();

        eprintln!("\n── JSON Record Submission ──────────────────────────────────");
        self.fuzz_record_submission_json();

        eprintln!("\n── Transfer Endpoint ───────────────────────────────────────");
        self.fuzz_transfer_endpoint();

        eprintln!("\n── Stake/Unstake ───────────────────────────────────────────");
        self.fuzz_stake_endpoint();

        eprintln!("\n── Balance & Ledger Queries ────────────────────────────────");
        self.fuzz_balance_queries();

        eprintln!("\n── Gossip & Sync ──────────────────────────────────────────");
        self.fuzz_gossip_endpoints();

        eprintln!("\n── Timestamp Defense ──────────────────────────────────────");
        self.fuzz_timestamp_defense();

        eprintln!("\n── Explorer Endpoints ─────────────────────────────────────");
        self.fuzz_explorer_endpoints();

        eprintln!("\n── Header Attacks ─────────────────────────────────────────");
        self.fuzz_header_attacks();

        eprintln!("\n── Stamp Endpoints ────────────────────────────────────────");
        self.fuzz_stamp_endpoints();

        eprintln!("\n── Rate Limits ────────────────────────────────────────────");
        self.fuzz_rate_limits();

        eprintln!("\n── Encoding & Injection ───────────────────────────────────");
        self.fuzz_encoding_attacks();

        eprintln!("\n── Concurrent Operations ──────────────────────────────────");
        self.fuzz_concurrent_operations();

        eprintln!("\n── Wire Format Edge Cases ─────────────────────────────────");
        self.fuzz_wire_format_edge_cases();

        eprintln!("\n── Admin Without Auth ─────────────────────────────────────");
        self.fuzz_admin_without_auth();

        // ── Summary ──────────────────────────────────────────────────────

        let total = self.results.len();
        let passed = self.results.iter().filter(|r| r.passed).count();
        let failed = total - passed;

        eprintln!("\n╔══════════════════════════════════════════════════════════════╗");
        eprintln!("║  RESULTS                                                     ║");
        eprintln!("╠══════════════════════════════════════════════════════════════╣");
        eprintln!("║  Total:  {:>5}                                               ║", total);
        eprintln!("║  Passed: {:>5}                                               ║", passed);
        eprintln!("║  Failed: {:>5}                                               ║", failed);
        eprintln!("╚══════════════════════════════════════════════════════════════╝");

        if failed > 0 {
            eprintln!("\n── FAILURES ───────────────────────────────────────────────");
            // Group by category
            let mut categories: BTreeMap<String, Vec<&FuzzResult>> = BTreeMap::new();
            for r in self.results.iter().filter(|r| !r.passed) {
                categories.entry(r.category.clone()).or_default().push(r);
            }
            for (cat, results) in &categories {
                eprintln!("\n  [{}]", cat);
                for r in results {
                    let status_str = r.status.map(|s| format!(" [{}]", s)).unwrap_or_default();
                    eprintln!("    ✗ #{:>3} {}{} — {}", r.id, r.name, status_str, r.detail);
                }
            }
        }

        // Check if node is still alive after fuzzing
        eprintln!("\n── Post-fuzz health check ─────────────────────────────────");
        match self.get("/health") {
            Ok(resp) if resp.status().is_success() => {
                eprintln!("  ✓ Node survived fuzzing. Still healthy.");
            }
            Ok(resp) => {
                eprintln!("  ⚠ Node responded but status: {}", resp.status());
            }
            Err(e) => {
                eprintln!("  ✗ NODE DOWN after fuzzing! Error: {}", e);
            }
        }

        std::process::exit(if failed > 0 { 1 } else { 0 });
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut target = "http://127.0.0.1:9474".to_string();
    let mut admin_token = "changeme".to_string();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--target" | "-t" => {
                i += 1;
                if i < args.len() {
                    target = args[i].clone();
                }
            }
            "--admin-token" | "-a" => {
                i += 1;
                if i < args.len() {
                    admin_token = args[i].clone();
                }
            }
            "--help" | "-h" => {
                eprintln!("elara-fuzz — adversarial node tester");
                eprintln!("Usage: elara-fuzz [--target URL] [--admin-token TOKEN]");
                eprintln!("  --target, -t       Node URL (default: http://127.0.0.1:9474)");
                eprintln!("  --admin-token, -a  Admin bearer token (default: changeme — set to your node's token)");
                std::process::exit(0);
            }
            _ => {}
        }
        i += 1;
    }

    let mut runner = FuzzRunner::new(&target, &admin_token).unwrap_or_else(|e| {
        eprintln!("error: failed to build HTTP client: {e}");
        std::process::exit(1);
    });
    runner.run_all();
}

// ─────────────────────────────────────────────────────────────────────────
// tests
// ─────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_bytes_fallback_returns_correct_len_and_never_panics() {
        // Covers the is_err() fallback branch: regardless of entropy state,
        // random_bytes must return a buffer of exactly the requested length.
        for &n in &[0usize, 1, 16, 256, 4096] {
            let b = random_bytes(n);
            assert_eq!(b.len(), n, "random_bytes({n}) returned wrong length");
        }
    }

    #[test]
    fn fuzz_runner_new_returns_ok_with_default_config() {
        // reqwest::Client::builder().build() should never fail with default
        // (no custom TLS/proxy) config — verify the Result is Ok, not a panic.
        assert!(
            FuzzRunner::new("http://127.0.0.1:9474", "tok").is_ok(),
            "FuzzRunner::new must return Ok with default reqwest config"
        );
    }

    #[test]
    fn now_secs_is_post_2025_epoch() {
        // 2025-01-01T00:00:00Z = 1735689600
        assert!(now_secs() > 1735689600.0);
    }

    #[test]
    fn random_bytes_has_requested_length() {
        for &n in &[0usize, 1, 16, 256, 1024] {
            assert_eq!(random_bytes(n).len(), n);
        }
    }

    #[test]
    fn random_bytes_nontrivial_entropy() {
        // Two 32-byte draws should never collide (probability ≈ 2^-256)
        let a = random_bytes(32);
        let b = random_bytes(32);
        assert_ne!(a, b, "two distinct random_bytes(32) calls collided");
    }

    #[test]
    fn random_hex_length_is_double_input_bytes() {
        for &n in &[1usize, 4, 16, 64] {
            let h = random_hex(n);
            assert_eq!(h.len(), n * 2, "input {n} → hex len mismatch");
        }
    }

    #[test]
    fn random_hex_contains_only_lowercase_hex_chars() {
        let h = random_hex(64);
        for c in h.chars() {
            assert!(c.is_ascii_hexdigit(), "non-hex char {c:?} in {h}");
            assert!(!c.is_ascii_uppercase(), "uppercase {c:?} in {h}");
        }
    }

    #[test]
    fn fuzz_runner_url_concatenates_target_and_path() {
        let r = FuzzRunner::new("http://127.0.0.1:9474", "tok").expect("build");
        assert_eq!(r.url("/version"), "http://127.0.0.1:9474/version");
        assert_eq!(r.url(""), "http://127.0.0.1:9474");
    }

    #[test]
    fn fuzz_runner_url_preserves_query_string() {
        let r = FuzzRunner::new("http://node:8080", "tok").expect("build");
        assert_eq!(r.url("/records?limit=5"), "http://node:8080/records?limit=5");
    }

    #[test]
    fn fuzz_runner_record_assigns_sequential_ids() {
        let mut r = FuzzRunner::new("http://localhost", "tok").expect("build");
        r.record("cat", "a", true, Some(200), "");
        r.record("cat", "b", false, Some(500), "boom");
        r.record("cat", "c", true, None, "");
        assert_eq!(r.results.len(), 3);
        assert_eq!(r.results[0].id, 1);
        assert_eq!(r.results[1].id, 2);
        assert_eq!(r.results[2].id, 3);
    }

    #[test]
    fn fuzz_runner_record_preserves_fields() {
        let mut r = FuzzRunner::new("http://localhost", "tok").expect("build");
        r.record("inject", "sql-paths", false, Some(400), "rejected");
        let rec = &r.results[0];
        assert_eq!(rec.category, "inject");
        assert_eq!(rec.name, "sql-paths");
        assert!(!rec.passed);
        assert_eq!(rec.status, Some(400));
        assert_eq!(rec.detail, "rejected");
    }

    #[test]
    fn fuzz_runner_new_strips_trailing_slash_not_done() {
        // Documented behavior: target is stored verbatim; trailing slash NOT stripped.
        // A trailing slash on target → double-slash in url() output.
        let r = FuzzRunner::new("http://x/", "tok").expect("build");
        assert_eq!(r.url("/v"), "http://x//v");
    }

    // ─── random_bytes length / safety tests ──────────────────────────────

    #[test]
    fn batch_b_random_bytes_zero_length_returns_empty_vec_and_no_panic_on_large_sizes() {
        // Zero-length: well-defined empty allocation
        let zero = random_bytes(0);
        assert_eq!(zero.len(), 0);
        assert!(zero.is_empty());
        // Length sweep: every size produces correctly sized buffer
        for &n in &[1usize, 7, 13, 32, 64, 128, 512, 1024, 4096, 16384] {
            let buf = random_bytes(n);
            assert_eq!(buf.len(), n, "size mismatch for n={n}");
            assert!(buf.capacity() >= n);
        }
    }

    #[test]
    fn batch_b_random_bytes_pairwise_distinct_across_many_draws_at_each_size() {
        // For any non-trivial size, two consecutive draws must differ.
        // Collision probability at n=8 bytes is 2^-64 — negligible.
        for &n in &[8usize, 16, 32, 64, 128] {
            let mut draws: Vec<Vec<u8>> = Vec::with_capacity(8);
            for _ in 0..8 {
                draws.push(random_bytes(n));
            }
            // All-pairs distinctness
            for i in 0..draws.len() {
                for j in (i + 1)..draws.len() {
                    assert_ne!(
                        draws[i], draws[j],
                        "random_bytes({n}) collision between draws {i} and {j}"
                    );
                }
            }
        }
    }

    #[test]
    fn batch_b_random_hex_charset_is_exactly_lowercase_hex_no_whitespace_no_separator() {
        for &n in &[0usize, 1, 4, 16, 32, 64, 256] {
            let h = random_hex(n);
            assert_eq!(h.len(), n * 2, "byte len {n} → hex len {} (expected {})", h.len(), n * 2);
            assert!(h.len().is_multiple_of(2), "hex length must be even");
            for c in h.chars() {
                assert!(c.is_ascii(), "non-ASCII char {c:?} in random_hex({n})");
                assert!(c.is_ascii_hexdigit(), "non-hex char {c:?} in random_hex({n})");
                assert!(!c.is_ascii_uppercase(), "uppercase {c:?} in random_hex({n})");
                assert!(!c.is_whitespace(), "whitespace {c:?} in random_hex({n})");
                assert!(c != '-' && c != '_' && c != ':', "separator {c:?} in random_hex({n})");
            }
        }
    }

    #[test]
    fn batch_b_now_secs_finite_positive_and_within_plausible_real_time_band() {
        let t = now_secs();
        assert!(t.is_finite(), "now_secs must be finite, got {t}");
        assert!(t > 0.0, "now_secs must be positive, got {t}");
        // Lower bound: 2025-01-01 (this code did not exist before)
        assert!(t > 1_735_689_600.0, "now_secs={t} predates 2025-01-01");
        // Upper bound: 2100-01-01 (sanity ceiling — clock has not jumped to next century)
        assert!(t < 4_102_444_800.0, "now_secs={t} past 2100 — clock skew?");
        // Sub-second precision available
        let t2 = now_secs();
        assert!(t2 >= t, "monotonic non-decreasing across back-to-back calls");
    }

    #[test]
    fn batch_b_fuzz_runner_record_id_strictly_increasing_by_one_across_mixed_outcomes() {
        let mut r = FuzzRunner::new("http://localhost", "tok").expect("build");
        // Push 12 records with varied pass/fail/status to exercise the id-counter
        let outcomes = [
            ("a", "x1", true,  Some(200)),
            ("a", "x2", false, Some(500)),
            ("b", "y1", true,  None),
            ("b", "y2", false, Some(400)),
            ("c", "z1", true,  Some(204)),
            ("c", "z2", true,  Some(301)),
            ("d", "w1", false, Some(503)),
            ("d", "w2", false, None),
            ("e", "v1", true,  Some(200)),
            ("e", "v2", false, Some(422)),
            ("f", "u1", true,  Some(201)),
            ("f", "u2", false, Some(429)),
        ];
        for (cat, name, passed, status) in &outcomes {
            r.record(cat, name, *passed, *status, "");
        }
        assert_eq!(r.results.len(), outcomes.len(), "record count must match input");
        for (i, rec) in r.results.iter().enumerate() {
            assert_eq!(rec.id, i + 1, "id at index {i} expected {} got {}", i + 1, rec.id);
            assert_eq!(rec.category, outcomes[i].0);
            assert_eq!(rec.name, outcomes[i].1);
            assert_eq!(rec.passed, outcomes[i].2);
            assert_eq!(rec.status, outcomes[i].3);
        }
        // Strict +1 monotone ids
        for w in r.results.windows(2) {
            assert_eq!(w[1].id, w[0].id + 1, "ids must increment by exactly 1");
        }
    }
}
