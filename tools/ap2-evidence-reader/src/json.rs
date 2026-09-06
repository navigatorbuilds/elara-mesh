//! Strict JSON (RFC 8259) parser that REJECTS duplicate object keys at any depth
//! (SPEC_AP2_EVIDENCE.md §1), plus a canonical serializer reproducing Python's
//! `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)`
//! — the normative canonical form of §3.
//!
//! Documented divergences from Python's `json.loads` (all fail-closed):
//!   * lone UTF-16 surrogate escapes are rejected (Python accepts them);
//!   * the non-JSON literals `NaN` / `Infinity` / `-Infinity` are rejected.

use std::fmt::Write as _;

#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    /// Integer literal, normalised decimal text (arbitrary precision, like a Python int).
    Int(String),
    Float(f64),
    Str(String),
    Arr(Vec<Value>),
    /// Insertion order preserved; keys unique (the parser rejects duplicates).
    Obj(Vec<(String, Value)>),
}

impl Value {
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Obj(e) => e.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        if let Value::Str(s) = self {
            Some(s)
        } else {
            None
        }
    }
    pub fn as_bool(&self) -> Option<bool> {
        if let Value::Bool(b) = self {
            Some(*b)
        } else {
            None
        }
    }
    pub fn as_arr(&self) -> Option<&[Value]> {
        if let Value::Arr(a) = self {
            Some(a)
        } else {
            None
        }
    }
    pub fn as_obj(&self) -> Option<&[(String, Value)]> {
        if let Value::Obj(o) = self {
            Some(o)
        } else {
            None
        }
    }
    pub fn obj(entries: Vec<(&str, Value)>) -> Value {
        Value::Obj(entries.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
    }
    pub fn str(s: &str) -> Value {
        Value::Str(s.to_string())
    }
}

pub fn parse(text: &str) -> Result<Value, String> {
    let mut p = Parser { s: text.as_bytes(), i: 0, depth: 0 };
    p.ws();
    let v = p.value()?;
    p.ws();
    if p.i != p.s.len() {
        return Err(format!("trailing characters at offset {}", p.i));
    }
    Ok(v)
}

const MAX_DEPTH: usize = 512;

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
    depth: usize,
}

impl<'a> Parser<'a> {
    fn ws(&mut self) {
        while self.i < self.s.len() && matches!(self.s[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
    }
    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }
    fn err<T>(&self, msg: &str) -> Result<T, String> {
        Err(format!("{msg} at offset {}", self.i))
    }
    fn value(&mut self) -> Result<Value, String> {
        match self.peek() {
            None => self.err("unexpected end of input"),
            Some(b'{') => self.object(),
            Some(b'[') => self.array(),
            Some(b'"') => Ok(Value::Str(self.string()?)),
            Some(b't') => self.literal("true", Value::Bool(true)),
            Some(b'f') => self.literal("false", Value::Bool(false)),
            Some(b'n') => self.literal("null", Value::Null),
            Some(c) if c == b'-' || c.is_ascii_digit() => self.number(),
            Some(_) => self.err("unexpected character"),
        }
    }
    fn literal(&mut self, lit: &str, v: Value) -> Result<Value, String> {
        if self.s[self.i..].starts_with(lit.as_bytes()) {
            self.i += lit.len();
            Ok(v)
        } else {
            self.err("invalid literal")
        }
    }
    fn enter(&mut self) -> Result<(), String> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return self.err("nesting too deep");
        }
        Ok(())
    }
    fn object(&mut self) -> Result<Value, String> {
        self.enter()?;
        self.i += 1;
        let mut entries: Vec<(String, Value)> = Vec::new();
        self.ws();
        if self.peek() == Some(b'}') {
            self.i += 1;
            self.depth -= 1;
            return Ok(Value::Obj(entries));
        }
        loop {
            self.ws();
            if self.peek() != Some(b'"') {
                return self.err("expected string key");
            }
            let k = self.string()?;
            if entries.iter().any(|(e, _)| *e == k) {
                return Err(format!("duplicate object key {k:?} at offset {}", self.i));
            }
            self.ws();
            if self.peek() != Some(b':') {
                return self.err("expected ':'");
            }
            self.i += 1;
            self.ws();
            let v = self.value()?;
            entries.push((k, v));
            self.ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b'}') => {
                    self.i += 1;
                    break;
                }
                _ => return self.err("expected ',' or '}'"),
            }
        }
        self.depth -= 1;
        Ok(Value::Obj(entries))
    }
    fn array(&mut self) -> Result<Value, String> {
        self.enter()?;
        self.i += 1;
        let mut items = Vec::new();
        self.ws();
        if self.peek() == Some(b']') {
            self.i += 1;
            self.depth -= 1;
            return Ok(Value::Arr(items));
        }
        loop {
            self.ws();
            items.push(self.value()?);
            self.ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b']') => {
                    self.i += 1;
                    break;
                }
                _ => return self.err("expected ',' or ']'"),
            }
        }
        self.depth -= 1;
        Ok(Value::Arr(items))
    }
    fn string(&mut self) -> Result<String, String> {
        self.i += 1;
        let mut out = String::new();
        loop {
            let c = match self.peek() {
                None => return self.err("unterminated string"),
                Some(c) => c,
            };
            match c {
                b'"' => {
                    self.i += 1;
                    return Ok(out);
                }
                b'\\' => {
                    self.i += 1;
                    let e = match self.peek() {
                        None => return self.err("unterminated escape"),
                        Some(e) => e,
                    };
                    self.i += 1;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let hi = self.hex4()?;
                            let cp = if (0xD800..0xDC00).contains(&hi) {
                                if self.s[self.i..].starts_with(b"\\u") {
                                    self.i += 2;
                                    let lo = self.hex4()?;
                                    if !(0xDC00..0xE000).contains(&lo) {
                                        return self.err("invalid low surrogate");
                                    }
                                    0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                                } else {
                                    return self.err("lone high surrogate (rejected fail-closed)");
                                }
                            } else if (0xDC00..0xE000).contains(&hi) {
                                return self.err("lone low surrogate (rejected fail-closed)");
                            } else {
                                hi
                            };
                            out.push(char::from_u32(cp).ok_or_else(|| "invalid code point".to_string())?);
                        }
                        _ => return self.err("invalid escape"),
                    }
                }
                c if c < 0x20 => return self.err("control character in string"),
                _ => {
                    let start = self.i;
                    self.i += utf8_len(c);
                    let piece = self
                        .s
                        .get(start..self.i)
                        .ok_or_else(|| "truncated UTF-8 sequence".to_string())?;
                    out.push_str(std::str::from_utf8(piece).map_err(|e| e.to_string())?);
                }
            }
        }
    }
    fn hex4(&mut self) -> Result<u32, String> {
        if self.i + 4 > self.s.len() {
            return self.err("short \\u escape");
        }
        let h = std::str::from_utf8(&self.s[self.i..self.i + 4]).map_err(|e| e.to_string())?;
        let v = u32::from_str_radix(h, 16).map_err(|_| format!("bad \\u escape at offset {}", self.i))?;
        self.i += 4;
        Ok(v)
    }
    fn number(&mut self) -> Result<Value, String> {
        let start = self.i;
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        match self.peek() {
            Some(b'0') => self.i += 1,
            Some(c) if (b'1'..=b'9').contains(&c) => {
                while matches!(self.peek(), Some(d) if d.is_ascii_digit()) {
                    self.i += 1;
                }
            }
            _ => return self.err("invalid number"),
        }
        let mut is_float = false;
        if self.peek() == Some(b'.') {
            is_float = true;
            self.i += 1;
            if !matches!(self.peek(), Some(d) if d.is_ascii_digit()) {
                return self.err("invalid fraction");
            }
            while matches!(self.peek(), Some(d) if d.is_ascii_digit()) {
                self.i += 1;
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            is_float = true;
            self.i += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.i += 1;
            }
            if !matches!(self.peek(), Some(d) if d.is_ascii_digit()) {
                return self.err("invalid exponent");
            }
            while matches!(self.peek(), Some(d) if d.is_ascii_digit()) {
                self.i += 1;
            }
        }
        let text = std::str::from_utf8(&self.s[start..self.i]).map_err(|e| e.to_string())?;
        if is_float {
            let f: f64 = text.parse().map_err(|_| format!("bad float {text}"))?;
            Ok(Value::Float(f))
        } else if text.trim_start_matches('-').bytes().all(|b| b == b'0') {
            Ok(Value::Int("0".into()))
        } else {
            Ok(Value::Int(text.to_string()))
        }
    }
}

fn utf8_len(first: u8) -> usize {
    if first < 0x80 {
        1
    } else if first >> 5 == 0b110 {
        2
    } else if first >> 4 == 0b1110 {
        3
    } else {
        4
    }
}

/// Python `json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=True)`.
pub fn canonical(v: &Value) -> String {
    let mut out = String::new();
    write_canonical(v, &mut out);
    out
}

fn write_canonical(v: &Value, out: &mut String) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Int(t) => out.push_str(t),
        Value::Float(f) => out.push_str(&python_float_repr(*f)),
        Value::Str(s) => write_python_ascii_string(s, out),
        Value::Arr(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(x, out);
            }
            out.push(']');
        }
        Value::Obj(o) => {
            // Python sorts keys by code point; Rust String order (UTF-8 bytes) is the same order.
            let mut refs: Vec<&(String, Value)> = o.iter().collect();
            refs.sort_by(|a, b| a.0.cmp(&b.0));
            out.push('{');
            for (i, (k, x)) in refs.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_python_ascii_string(k, out);
                out.push(':');
                write_canonical(x, out);
            }
            out.push('}');
        }
    }
}

/// Python's ESCAPE_ASCII: `"` `\` and the five short escapes; everything outside
/// 0x20..=0x7E becomes lowercase `\uXXXX` (UTF-16 surrogate pairs above the BMP).
fn write_python_ascii_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (' '..='~').contains(&c) => out.push(c),
            c => {
                let cp = c as u32;
                if cp < 0x10000 {
                    let _ = write!(out, "\\u{cp:04x}");
                } else {
                    let v = cp - 0x10000;
                    let _ = write!(out, "\\u{:04x}\\u{:04x}", 0xD800 + (v >> 10), 0xDC00 + (v & 0x3FF));
                }
            }
        }
    }
    out.push('"');
}

/// Python `repr(float)`: shortest round-trip digits; fixed notation when the
/// decimal-point position is in (-4, 16], else `d.ddde+XX` with a signed
/// two-digit-minimum exponent.
pub fn python_float_repr(f: f64) -> String {
    if f.is_nan() {
        return "NaN".into();
    }
    if f.is_infinite() {
        return if f > 0.0 { "Infinity" } else { "-Infinity" }.into();
    }
    if f == 0.0 {
        return if f.is_sign_negative() { "-0.0" } else { "0.0" }.into();
    }
    let sci = format!("{:e}", f.abs());
    let (mant, exp) = sci.split_once('e').unwrap_or((sci.as_str(), "0"));
    let exp: i32 = exp.parse().unwrap_or(0);
    let digits: String = mant.chars().filter(|c| *c != '.').collect();
    let decpt = exp + 1;
    let sign = if f < 0.0 { "-" } else { "" };
    if -4 < decpt && decpt <= 16 {
        if decpt <= 0 {
            format!("{sign}0.{}{digits}", "0".repeat((-decpt) as usize))
        } else if decpt as usize >= digits.len() {
            format!("{sign}{digits}{}.0", "0".repeat(decpt as usize - digits.len()))
        } else {
            format!("{sign}{}.{}", &digits[..decpt as usize], &digits[decpt as usize..])
        }
    } else {
        let e = decpt - 1;
        let m = if digits.len() > 1 {
            format!("{}.{}", &digits[..1], &digits[1..])
        } else {
            digits.clone()
        };
        format!("{sign}{m}e{}{:02}", if e < 0 { "-" } else { "+" }, e.abs())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_duplicate_keys_at_any_depth() {
        assert!(parse(r#"{"a":1,"a":2}"#).is_err());
        assert!(parse(r#"{"a":{"b":1,"b":2}}"#).is_err());
        assert!(parse(r#"[{"x":1},{"x":1,"x":2}]"#).is_err());
        assert!(parse(r#"{"a":1,"b":{"a":1}}"#).is_ok());
    }

    #[test]
    fn canonical_matches_python() {
        let v = parse("{\"b\":[1,2.5,true,null],\"a\":\"h\\u00e9 \\u2014 \\ud83d\\ude00 \\\"q\\\" \\u007f\"}").unwrap();
        assert_eq!(
            canonical(&v),
            "{\"a\":\"h\\u00e9 \\u2014 \\ud83d\\ude00 \\\"q\\\" \\u007f\",\"b\":[1,2.5,true,null]}"
        );
    }

    #[test]
    fn float_repr_matches_python() {
        for (f, want) in [
            (1.0, "1.0"),
            (0.0001, "0.0001"),
            (0.00001, "1e-05"),
            (1e16, "1e+16"),
            (1e15, "1000000000000000.0"),
            (123.456, "123.456"),
            (-2.5e-7, "-2.5e-07"),
            (1.5e300, "1.5e+300"),
        ] {
            assert_eq!(python_float_repr(f), want, "{f}");
        }
    }
}
