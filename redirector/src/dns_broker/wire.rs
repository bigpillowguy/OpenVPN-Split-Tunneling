//! Bounded DNS framing and envelope validation. RDATA stays opaque so native
//! clients retain DNS record semantics rather than receiving reconstructed data.
pub const MAX_QUERY: usize = 4096;
pub const MAX_RESPONSE: usize = 65535;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Question {
    labels: Vec<Vec<u8>>,
    kind: u16,
    class: u16,
}

impl Question {
    pub fn kind(&self) -> u16 {
        self.kind
    }
}

/// Header-only metadata for already validated responses. The low four RCODE
/// bits are reported explicitly; EDNS extended errors are not mislabelled here.
pub fn response_header(bytes: &[u8]) -> Option<(u8, bool, u16)> {
    (bytes.len() >= 12).then(|| {
        (
            bytes[3] & 0x0f,
            bytes[2] & 2 != 0,
            u16::from_be_bytes([bytes[6], bytes[7]]),
        )
    })
}

fn word(bytes: &[u8], at: usize) -> Result<u16, ()> {
    let b = bytes.get(at..at + 2).ok_or(())?;
    Ok(u16::from_be_bytes([b[0], b[1]]))
}

fn name(bytes: &[u8], start: usize) -> Result<(Vec<Vec<u8>>, usize), ()> {
    let mut at = start;
    let mut end = None;
    let mut labels = Vec::new();
    let mut expanded = 1;
    // Backward-only pointers prevent loops; the hop cap also bounds hostile work.
    for _ in 0..128 {
        let length = *bytes.get(at).ok_or(())?;
        if length & 0xc0 == 0xc0 {
            let destination = usize::from(word(bytes, at)? & 0x3fff);
            if destination < 12 || destination >= at {
                return Err(());
            }
            end.get_or_insert(at + 2);
            at = destination;
        } else if length & 0xc0 != 0 {
            return Err(());
        } else if length == 0 {
            return Ok((labels, end.unwrap_or(at + 1)));
        } else {
            at += 1;
            let label = bytes.get(at..at + usize::from(length)).ok_or(())?;
            expanded += label.len() + 1;
            if expanded > 255 {
                return Err(());
            }
            labels.push(label.iter().map(u8::to_ascii_lowercase).collect());
            at += label.len();
        }
    }
    Err(())
}

fn question(bytes: &[u8]) -> Result<(Question, usize), ()> {
    if bytes.len() < 12 || word(bytes, 4)? != 1 {
        return Err(());
    }
    let (labels, at) = name(bytes, 12)?;
    Ok((
        Question {
            labels,
            kind: word(bytes, at)?,
            class: word(bytes, at + 2)?,
        },
        at + 4,
    ))
}

fn records(bytes: &[u8], mut at: usize) -> Result<(), ()> {
    let count =
        u32::from(word(bytes, 6)?) + u32::from(word(bytes, 8)?) + u32::from(word(bytes, 10)?);
    // Every RR needs an owner plus a ten-byte fixed part.
    if count as usize > bytes.len() / 11 {
        return Err(());
    }
    for _ in 0..count {
        at = name(bytes, at)?.1;
        let length = usize::from(word(bytes, at + 8)?);
        at = at.checked_add(10 + length).ok_or(())?;
        if at > bytes.len() {
            return Err(());
        }
    }
    if at != bytes.len() {
        return Err(());
    }
    Ok(())
}

pub fn query(bytes: &[u8]) -> Result<Question, ()> {
    if !(12..=MAX_QUERY).contains(&bytes.len()) {
        return Err(());
    }
    let flags = word(bytes, 2)?;
    // Ordinary QUERY only. UPDATE, responses, truncated queries and transfers
    // cannot be represented as one bounded request/response exchange.
    if flags & 0xfa40 != 0 || word(bytes, 6)? != 0 || word(bytes, 8)? != 0 {
        return Err(());
    }
    let (question, at) = question(bytes)?;
    if question.class != 1 || matches!(question.kind, 251 | 252) {
        return Err(());
    }
    records(bytes, at)?;
    Ok(question)
}

#[derive(Debug, PartialEq, Eq)]
pub enum Response {
    Complete,
    Truncated,
}

pub fn response(bytes: &[u8], id: u16, expected: &Question) -> Result<Response, ()> {
    if !(12..=MAX_RESPONSE).contains(&bytes.len()) || word(bytes, 0)? != id {
        return Err(());
    }
    let flags = word(bytes, 2)?;
    if flags & 0x8000 == 0 || flags & 0x7840 != 0 {
        return Err(());
    }
    let (actual, at) = question(bytes)?;
    if &actual != expected {
        return Err(());
    }
    // A truncated UDP answer may end partway through its record section.
    if flags & 0x0200 != 0 {
        return Ok(Response::Truncated);
    }
    records(bytes, at)?;
    Ok(Response::Complete)
}

#[cfg(test)]
pub fn test_query() -> Vec<u8> {
    vec![
        0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 4, b't', b'e', b's', b't', 7, b'i', b'n', b'v',
        b'a', b'l', b'i', b'd', 0, 0, 1, 0, 1,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_truncation_bombs_pointer_cycles_and_unsupported_operations() {
        let q = test_query();
        assert!(query(&q).is_ok());
        for n in 0..q.len() {
            assert!(query(&q[..n]).is_err());
        }
        for (at, value) in [(2, 0x80), (2, 0x29), (5, 2), (6, 1), (12, 0xc0), (12, 64)] {
            let mut bad = q.clone();
            bad[at] = value;
            assert!(query(&bad).is_err());
        }
        let mut bad = q;
        bad.extend_from_slice(&[0]);
        assert!(query(&bad).is_err());
    }
    #[test]
    fn validates_question_and_id_and_preserves_negative_answers() {
        let q = test_query();
        let expected = query(&q).unwrap();
        let mut reply = q.clone();
        reply[2] = 0x81;
        reply[3] = 0x83;
        assert_eq!(response(&reply, 0x1234, &expected), Ok(Response::Complete));
        assert!(response(&reply, 0x9999, &expected).is_err());
        reply[13] = b'x';
        assert!(response(&reply, 0x1234, &expected).is_err());
        reply = q;
        reply[2] = 0x83;
        reply[7] = 1;
        assert_eq!(response(&reply, 0x1234, &expected), Ok(Response::Truncated));
        reply[2] = 0x81;
        assert!(response(&reply, 0x1234, &expected).is_err());
    }
}
