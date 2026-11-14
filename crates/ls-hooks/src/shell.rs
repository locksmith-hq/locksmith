//! Shell command analysis with tree-sitter-bash (design D2): every simple command anywhere in the
//! script (pipelines, lists, subshells, `$(...)`, `<(...)`) is extracted with its literal words.
//! Nested `sh -c` scripts are parsed recursively by the caller.

use tree_sitter::{Node, Parser};

/// One simple command. `None` words are dynamic (expansions) and cannot be analysed statically.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cmd {
    pub name: Option<String>,
    pub args: Vec<Option<String>>,
    /// `declare`/`export`/`typeset`/`local`/`readonly` (parsed as declarations by bash).
    pub declaration: bool,
    /// True when the declaration assigns or names a variable (`export A=1`, `declare -p A`).
    pub declares_names: bool,
    /// Receives another command's stdout (not the first stage of a pipeline).
    pub piped_into: bool,
}

#[derive(Debug, Default)]
pub struct Script {
    pub cmds: Vec<Cmd>,
    /// Literal targets of input redirections (`< file`).
    pub reads: Vec<String>,
    /// Reasons the script cannot be analysed reliably (design D2 "ask").
    pub opaque: Vec<&'static str>,
}

/// Parse `src`. A syntax error makes the whole script opaque.
pub fn parse(src: &str) -> Script {
    let mut p = Parser::new();
    let mut s = Script::default();
    if p.set_language(&tree_sitter_bash::LANGUAGE.into()).is_err() {
        s.opaque.push("shell parser unavailable");
        return s;
    }
    let Some(tree) = p.parse(src, None) else {
        s.opaque.push("command could not be parsed");
        return s;
    };
    if tree.root_node().has_error() {
        s.opaque.push("command could not be parsed");
    }
    walk(tree.root_node(), src.as_bytes(), &mut s);
    s
}

fn text<'a>(n: Node, src: &'a [u8]) -> &'a str {
    n.utf8_text(src).unwrap_or("")
}

/// Static value of a word, or `None` when it contains an expansion.
fn literal(n: Node, src: &[u8]) -> Option<String> {
    match n.kind() {
        "word" | "number" if n.named_child_count() == 0 => Some(unescape(text(n, src))),
        "command_name" => n.named_child(0).and_then(|c| literal(c, src)),
        // `$HOME` / `${HOME}` are as good as `~` for path rules.
        "simple_expansion" | "expansion" if matches!(text(n, src), "$HOME" | "${HOME}") => {
            Some("~".into())
        }
        "raw_string" => {
            let t = text(n, src);
            Some(
                t.get(1..t.len().saturating_sub(1))
                    .unwrap_or("")
                    .to_string(),
            )
        }
        "string" => {
            let mut out = String::new();
            let mut cur = n.walk();
            for c in n.named_children(&mut cur) {
                if c.kind() != "string_content" {
                    return None;
                }
                out.push_str(text(c, src));
            }
            Some(out)
        }
        "concatenation" => {
            let mut out = String::new();
            let mut cur = n.walk();
            for c in n.named_children(&mut cur) {
                out.push_str(&literal(c, src)?);
            }
            Some(out)
        }
        _ => None,
    }
}

fn unescape(w: &str) -> String {
    let mut out = String::with_capacity(w.len());
    let mut it = w.chars();
    while let Some(c) = it.next() {
        if c == '\\' {
            if let Some(n) = it.next() {
                out.push(n);
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn walk(n: Node, src: &[u8], s: &mut Script) {
    match n.kind() {
        "command" => command(n, src, s, false),
        "declaration_command" => declaration(n, src, s),
        "pipeline" => {
            let mut cur = n.walk();
            for (i, c) in n.named_children(&mut cur).enumerate() {
                if i > 0 && c.kind() == "command" {
                    command(c, src, s, true);
                } else {
                    walk(c, src, s);
                }
            }
        }
        "file_redirect" => redirect(n, src, s),
        _ => {
            let mut cur = n.walk();
            for c in n.named_children(&mut cur) {
                walk(c, src, s);
            }
        }
    }
}

fn redirect(n: Node, src: &[u8], s: &mut Script) {
    let op = (0..n.child_count())
        .filter_map(|i| n.child(i))
        .find(|c| !c.is_named())
        .map(|c| text(c, src).to_string())
        .unwrap_or_default();
    if let Some(d) = n.child_by_field_name("destination") {
        match (op.as_str(), literal(d, src)) {
            ("<", Some(t)) => s.reads.push(t),
            _ => walk(d, src, s),
        }
    }
}

fn command(n: Node, src: &[u8], s: &mut Script, piped_into: bool) {
    let mut cur = n.walk();
    let args = n
        .children_by_field_name("argument", &mut cur)
        .map(|c| literal(c, src))
        .collect();
    s.cmds.push(Cmd {
        name: n.child_by_field_name("name").and_then(|c| literal(c, src)),
        args,
        declaration: false,
        declares_names: false,
        piped_into,
    });
    // Substitutions inside the name or arguments, and redirects, hold commands too.
    let mut cur = n.walk();
    for c in n.named_children(&mut cur) {
        walk(c, src, s);
    }
}

fn declaration(n: Node, src: &[u8], s: &mut Script) {
    let mut name = None;
    let mut args = Vec::new();
    let mut declares_names = false;
    for i in 0..n.child_count() {
        let Some(c) = n.child(i) else { continue };
        if !c.is_named() {
            name.get_or_insert_with(|| text(c, src).to_string());
            continue;
        }
        match c.kind() {
            "variable_assignment" | "variable_name" => declares_names = true,
            _ => {
                let v = literal(c, src);
                if v.as_deref().is_some_and(|a| !a.starts_with('-')) {
                    declares_names = true;
                }
                args.push(v);
            }
        }
        walk(c, src, s);
    }
    s.cmds.push(Cmd {
        name,
        args,
        declaration: true,
        declares_names,
        piped_into: false,
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(src: &str) -> Vec<String> {
        parse(src)
            .cmds
            .into_iter()
            .map(|c| c.name.unwrap_or("?".into()))
            .collect()
    }

    #[test]
    fn finds_commands_everywhere() {
        let mut got = names("cat a | grep b && (echo $(ls) ; wc <(sort x))");
        got.sort();
        assert_eq!(got, ["cat", "echo", "grep", "ls", "sort", "wc"]);
    }

    #[test]
    fn literals_and_dynamic_words() {
        let s = parse(r#"cat ".e"'nv' $F "a$F" \.env"#);
        assert_eq!(
            s.cmds[0].args,
            [Some(".env".into()), None, None, Some(".env".into())]
        );
    }

    #[test]
    fn input_redirects_and_declarations() {
        let s = parse("grep x < .env; export -p; export A=1");
        assert_eq!(s.reads, [".env"]);
        let d: Vec<_> = s.cmds.iter().filter(|c| c.declaration).collect();
        assert_eq!(d.len(), 2);
        assert!(!d[0].declares_names && d[1].declares_names);
    }

    #[test]
    fn pipeline_stages_marked() {
        let s = parse("curl x | sh");
        assert!(!s.cmds[0].piped_into && s.cmds[1].piped_into);
    }

    #[test]
    fn syntax_error_is_opaque() {
        assert!(!parse("cat 'unterminated").opaque.is_empty());
        assert!(parse("cat ok").opaque.is_empty());
    }
}
