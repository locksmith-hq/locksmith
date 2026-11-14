//! Minimal `.env` parser: comments, `export ` prefixes, bare / 'single' / "double" quoted values,
//! multiline quoted values. Errors name a line number, never a value.

use ls_crypto::SecretBytes;

fn valid_key(k: &str) -> bool {
    !k.is_empty()
        && !k.starts_with(|c: char| c.is_ascii_digit())
        && k.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

pub fn parse(src: &str) -> Result<Vec<(String, SecretBytes)>, String> {
    let mut out = Vec::new();
    let mut lines = src.lines().enumerate();
    while let Some((n, raw)) = lines.next() {
        let line = raw.trim_start();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = match line.strip_prefix("export") {
            Some(r) if r.starts_with([' ', '\t']) => r.trim_start(),
            _ => line,
        };
        let (key, rest) = line
            .split_once('=')
            .ok_or_else(|| format!("line {}: expected KEY=VALUE", n + 1))?;
        let key = key.trim();
        if !valid_key(key) {
            return Err(format!("line {}: invalid key name", n + 1));
        }
        let rest = rest.trim_start();
        let value = match rest.chars().next() {
            Some(q @ ('"' | '\'')) => {
                // Accumulate across lines until the closing quote.
                let mut buf = String::new();
                let mut cur = rest[1..].to_string();
                let tail = loop {
                    let mut esc = false;
                    let mut end = None;
                    for (i, c) in cur.char_indices() {
                        if q == '"' && esc {
                            match c {
                                'n' => buf.push('\n'),
                                'r' => buf.push('\r'),
                                't' => buf.push('\t'),
                                '"' | '\\' | '$' | '`' => buf.push(c),
                                other => {
                                    buf.push('\\');
                                    buf.push(other);
                                }
                            }
                            esc = false;
                        } else if q == '"' && c == '\\' {
                            esc = true;
                        } else if c == q {
                            end = Some(i + 1);
                            break;
                        } else {
                            buf.push(c);
                        }
                    }
                    if let Some(e) = end {
                        break cur[e..].to_string();
                    }
                    let (_, next) = lines
                        .next()
                        .ok_or_else(|| format!("line {}: unterminated quoted value", n + 1))?;
                    buf.push('\n');
                    cur = next.to_string();
                };
                let t = tail.trim();
                if !(t.is_empty() || t.starts_with('#')) {
                    return Err(format!(
                        "line {}: unexpected text after closing quote",
                        n + 1
                    ));
                }
                buf
            }
            _ => {
                let end = rest
                    .char_indices()
                    .find(|&(i, c)| c == '#' && (i == 0 || rest[..i].ends_with([' ', '\t'])))
                    .map_or(rest.len(), |(i, _)| i);
                rest[..end].trim_end().to_string()
            }
        };
        out.push((key.to_string(), SecretBytes::new(value.into_bytes())));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_fixture() {
        let src = "# c\n\nA=plain\nexport B=\"quoted # not comment\" # tail\nC='single $x \\n'\nD=\"multi\nline \\\"q\\\"\\n\"\nE=bare # comment\nF=\nexport\tG=1\n";
        let got: Vec<(String, String)> = parse(src)
            .unwrap()
            .into_iter()
            .map(|(k, v)| (k, String::from_utf8(v.expose().to_vec()).unwrap()))
            .collect();
        let want = [
            ("A", "plain"),
            ("B", "quoted # not comment"),
            ("C", "single $x \\n"),
            ("D", "multi\nline \"q\"\n"),
            ("E", "bare"),
            ("F", ""),
            ("G", "1"),
        ];
        assert_eq!(got.len(), want.len());
        for (g, w) in got.iter().zip(want) {
            assert_eq!((g.0.as_str(), g.1.as_str()), w);
        }
    }

    #[test]
    fn errors_do_not_echo_values() {
        for bad in ["NOEQUALS", "1A=x", "K=\"never closed s3cret"] {
            let e = parse(bad).err().unwrap();
            assert!(!e.contains("s3cret"), "{e}");
        }
    }
}
