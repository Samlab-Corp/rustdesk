//! Dependency-free framing policy, also tested with `rustc --test`.
pub const MAX_INPUT: usize = 64 * 1024;
pub const MAX_OUTPUT: usize = 4 * 1024 * 1024;

pub fn valid_target(value: &str) -> bool {
    (3..=16).contains(&value.len()) && value.bytes().all(|b| b.is_ascii_digit())
}

pub struct OutputFrame {
    start: Vec<u8>,
    end: Vec<u8>,
    bytes: Vec<u8>,
    limit: usize,
    escape: u8,
    started: bool,
    line_start: usize,
}

impl OutputFrame {
    pub fn new(id: &str, limit: usize) -> Self {
        Self {
            start: format!("SAMLAB_START_{id}\n").into_bytes(),
            end: format!("SAMLAB_END_{id}:").into_bytes(),
            bytes: Vec::new(),
            limit,
            escape: 0,
            started: false,
            line_start: 0,
        }
    }
    pub fn feed(&mut self, chunk: &[u8]) -> Result<Option<(String, i32)>, ()> {
        for &b in chunk {
            // Strip VT control sequences across packet boundaries, not terminal text.
            match self.escape {
                1 => {
                    self.escape = if b == b'[' {
                        2
                    } else if b == b']' {
                        3
                    } else {
                        0
                    };
                    continue;
                }
                2 => {
                    if (0x40..=0x7e).contains(&b) {
                        self.escape = 0;
                    }
                    continue;
                }
                3 => {
                    if b == 7 {
                        self.escape = 0;
                    } else if b == 27 {
                        self.escape = 4;
                    }
                    continue;
                }
                4 => {
                    self.escape = if b == b'\\' { 0 } else { 3 };
                    continue;
                }
                _ => {}
            }
            if b == 27 {
                self.escape = 1;
                continue;
            }
            if b != b'\r' {
                self.bytes.push(b);
            }
            if !self.started {
                if self.bytes.ends_with(&self.start) {
                    self.started = true;
                    self.bytes.clear();
                } else if self.bytes.len() > self.start.len() {
                    self.bytes.remove(0);
                }
                continue;
            }
            if self.bytes.len() > self.limit + self.end.len() + 20 {
                return Err(());
            }
            if b == b'\n' {
                let offset = self.line_start;
                self.line_start = self.bytes.len();
                if self.bytes[offset..].starts_with(&self.end) {
                    let digits = &self.bytes[offset + self.end.len()..self.bytes.len() - 1];
                    if let Ok(code) = std::str::from_utf8(digits).unwrap_or("").parse::<i32>() {
                        if offset > self.limit {
                            return Err(());
                        }
                        return Ok(Some((
                            String::from_utf8_lossy(&self.bytes[..offset]).into_owned(),
                            code,
                        )));
                    }
                }
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn requires_explicit_numeric_target() {
        assert!(valid_target("000317"));
        assert!(!valid_target("all"));
        assert!(!valid_target("123@server?key=secret"));
        assert!(!valid_target(""));
    }
    #[test]
    fn ignores_echo_and_requires_matching_completion() {
        let mut f = OutputFrame::new("abc", 100);
        assert_eq!(f.feed(b"powershell -EncodedCommand hidden\r\nSAMLAB_START_abc\r\nhello\r\nSAMLAB_END_wrong:0\r\n").unwrap(), None);
        let (out, code) = f.feed(b"SAMLAB_END_abc:7\r\n").unwrap().unwrap();
        assert_eq!(out, "hello\nSAMLAB_END_wrong:0\n");
        assert_eq!(code, 7);
    }
    #[test]
    fn handles_fragmented_markers_and_vt_sequences() {
        let mut f = OutputFrame::new("x", 20);
        for b in b"\x1b[32mSAMLAB_START_x\r\n\x1b[0mhost\r\nSAMLAB_END_x:0\r" {
            assert!(f.feed(&[*b]).unwrap().is_none());
        }
        assert_eq!(f.feed(b"\n").unwrap(), Some(("host\n".into(), 0)));
    }
    #[test]
    fn output_limit_never_reports_success() {
        let mut f = OutputFrame::new("x", 2);
        assert!(f.feed(b"SAMLAB_START_x\nlong\nSAMLAB_END_x:0\n").is_err());
    }
    #[test]
    fn does_not_accept_embedded_or_unfinished_marker() {
        let mut f = OutputFrame::new("x", 100);
        assert_eq!(
            f.feed(b"SAMLAB_START_x\ntextSAMLAB_END_x:0\nSAMLAB_END_x:")
                .unwrap(),
            None
        );
    }
}
