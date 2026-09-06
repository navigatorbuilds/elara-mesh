//! Minimal DER reader (definite lengths, single-byte tags) — enough for
//! RFC 3161 TimeStampResp / CMS SignedData / X.509 walking.

#[derive(Clone, Copy, Debug)]
pub struct Tlv<'a> {
    pub tag: u8,
    pub content: &'a [u8],
    pub raw: &'a [u8],
}

pub fn read(buf: &[u8]) -> Result<(Tlv<'_>, &[u8]), String> {
    if buf.len() < 2 {
        return Err("DER: truncated".into());
    }
    let tag = buf[0];
    if tag & 0x1f == 0x1f {
        return Err("DER: multi-byte tags unsupported".into());
    }
    let l0 = buf[1] as usize;
    let (len, hl) = if l0 < 0x80 {
        (l0, 2)
    } else {
        let n = l0 & 0x7f;
        if n == 0 || n > 4 {
            return Err("DER: indefinite or oversized length".into());
        }
        if buf.len() < 2 + n {
            return Err("DER: truncated length".into());
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | buf[2 + i] as usize;
        }
        if len < 0x80 || (n > 1 && len < (1usize << (8 * (n - 1)))) {
            return Err("DER: non-minimal length encoding".into());
        }
        (len, 2 + n)
    };
    if buf.len() < hl + len {
        return Err("DER: content exceeds buffer".into());
    }
    Ok((
        Tlv { tag, content: &buf[hl..hl + len], raw: &buf[..hl + len] },
        &buf[hl + len..],
    ))
}

pub fn items(buf: &[u8]) -> Result<Vec<Tlv<'_>>, String> {
    let mut out = Vec::new();
    let mut rest = buf;
    while !rest.is_empty() {
        let (t, r) = read(rest)?;
        out.push(t);
        rest = r;
    }
    Ok(out)
}

pub fn seq<'a>(t: Option<&Tlv<'a>>, what: &str) -> Result<Vec<Tlv<'a>>, String> {
    let t = t.ok_or_else(|| format!("{what}: missing"))?;
    if t.tag != 0x30 {
        return Err(format!("{what}: expected SEQUENCE, got tag 0x{:02x}", t.tag));
    }
    items(t.content)
}

pub fn expect<'a>(t: Option<&Tlv<'a>>, tag: u8, what: &str) -> Result<&'a [u8], String> {
    let t = t.ok_or_else(|| format!("{what}: missing"))?;
    if t.tag != tag {
        return Err(format!("{what}: expected tag 0x{tag:02x}, got 0x{:02x}", t.tag));
    }
    Ok(t.content)
}

pub fn oid(t: Option<&Tlv>) -> Result<String, String> {
    let c = expect(t, 0x06, "OBJECT IDENTIFIER")?;
    if c.is_empty() {
        return Err("empty OID".into());
    }
    let mut parts: Vec<u64> = Vec::new();
    let mut acc: u64 = 0;
    let mut first = true;
    for &b in c {
        acc = (acc << 7) | (b & 0x7f) as u64;
        if b & 0x80 == 0 {
            if first {
                let (a, b2) = if acc >= 80 { (2, acc - 80) } else { (acc / 40, acc % 40) };
                parts.push(a);
                parts.push(b2);
                first = false;
            } else {
                parts.push(acc);
            }
            acc = 0;
        }
    }
    if acc != 0 {
        return Err("truncated OID arc".into());
    }
    Ok(parts.iter().map(|p| p.to_string()).collect::<Vec<_>>().join("."))
}

pub fn int_u32(t: Option<&Tlv>) -> Result<u32, String> {
    let c = expect(t, 0x02, "INTEGER")?;
    if c.is_empty() || c.len() > 5 {
        return Err("INTEGER out of range".into());
    }
    let mut v: u64 = 0;
    for &b in c {
        v = (v << 8) | b as u64;
    }
    u32::try_from(v).map_err(|_| "INTEGER out of range".to_string())
}

/// UTCTime / GeneralizedTime → "YYYYMMDDHHMMSS" (DER requires the trailing Z).
pub fn time(t: Option<&Tlv>) -> Result<String, String> {
    let t = t.ok_or("time: missing")?;
    let s = std::str::from_utf8(t.content).map_err(|_| "time: not ASCII")?;
    match t.tag {
        0x17 => {
            if s.len() != 13 || !s.ends_with('Z') {
                return Err(format!("UTCTime malformed: {s}"));
            }
            let yy: u32 = s[..2].parse().map_err(|_| "UTCTime year")?;
            let century = if yy < 50 { "20" } else { "19" };
            Ok(format!("{century}{}", &s[..12]))
        }
        0x18 => {
            if s.len() < 15 || !s.ends_with('Z') {
                return Err(format!("GeneralizedTime malformed: {s}"));
            }
            Ok(s[..14].to_string())
        }
        other => Err(format!("time: unexpected tag 0x{other:02x}")),
    }
}
