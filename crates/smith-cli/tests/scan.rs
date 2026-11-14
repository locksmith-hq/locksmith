//! e2e for `smith scan`: vault-aware and generic findings, staged vs working tree, and a
//! false-positive corpus. Vault values are `fake_...`; key-shaped strings are built at runtime.

mod common;
use common::*;
use std::process::Output;

const SECRET: &str = "fake_db_password_9f3a1c77";

fn s(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn scan(h: &Home, r: &Repo, args: &[&str]) -> Output {
    let mut full = vec!["scan"];
    full.extend_from_slice(args);
    let mut full2 = vec!["--passphrase-stdin"];
    full2.extend(full);
    let mut c = h.cmd(&full2);
    c.current_dir(&r.0);
    let mut ch = c.spawn().unwrap();
    use std::io::Write;
    let _ = ch
        .stdin
        .take()
        .unwrap()
        .write_all(format!("{PW}\n").as_bytes());
    ch.wait_with_output().unwrap()
}

fn ready() -> (Home, Repo) {
    let h = Home::new();
    h.ready();
    assert!(h.add("DATABASE_URL", SECRET).status.success());
    (h, Repo::new())
}

fn token() -> String {
    format!("{}{}", "ghp_", "A".repeat(36))
}

#[test]
fn vault_value_reports_file_line_key_never_value() {
    let (h, r) = ready();
    r.write(
        "src/db.js",
        &format!("const a = 1;\nconst u = \"{SECRET}\";\n"),
    );
    let o = scan(&h, &r, &[]);
    assert_eq!(o.status.code(), Some(1));
    assert_eq!(s(&o.stdout).trim(), "src/db.js:2: DATABASE_URL");
    assert!(!s(&o.stdout).contains(SECRET) && !s(&o.stderr).contains(SECRET));
    let j = scan(&h, &r, &["--json"]);
    let v: serde_json::Value = serde_json::from_slice(&j.stdout).unwrap();
    assert_eq!(v["findings"][0]["key"], "DATABASE_URL");
    assert_eq!(v["findings"][0]["line"], 2);
}

#[test]
fn clean_tree_exits_zero() {
    let (h, r) = ready();
    r.write("a.js", "console.log('hi');\n");
    assert_eq!(scan(&h, &r, &[]).status.code(), Some(0));
}

#[test]
fn generic_rule_and_no_vault() {
    let h = Home::new(); // no vault at all
    let r = Repo::new();
    r.write("cfg.txt", &format!("x\ntoken={}\n", token()));
    let o = scan(&h, &r, &[]);
    assert_eq!(o.status.code(), Some(1));
    assert_eq!(s(&o.stdout).trim(), "cfg.txt:2: github-token");
    let (h2, r2) = ready();
    r2.write("v.txt", SECRET);
    // --no-vault never prompts and ignores vault values
    assert_eq!(scan(&h2, &r2, &["--no-vault"]).status.code(), Some(0));
}

#[test]
fn staged_reads_the_index_and_gitignore_is_respected() {
    let (h, r) = ready();
    r.write("a.txt", SECRET);
    r.git(&["add", "a.txt"]);
    r.write("a.txt", "clean now\n"); // working tree is clean, index is not
    assert_eq!(scan(&h, &r, &["--staged"]).status.code(), Some(1));
    assert_eq!(scan(&h, &r, &[]).status.code(), Some(0));
    r.git(&["reset", "-q"]);
    r.write(".gitignore", "ignored/\n");
    r.write("ignored/x.txt", SECRET);
    r.write("bin.dat", &format!("\0{SECRET}"));
    assert_eq!(scan(&h, &r, &[]).status.code(), Some(0)); // ignored dir, binary file
}

#[test]
fn zero_false_positives_on_realistic_corpus() {
    let (h, r) = ready();
    let files: &[(&str, &str)] = &[
        (
            "src/index.ts",
            "import express from 'express';\nconst app = express();\nconst key = process.env.STRIPE_SECRET_KEY;\nconst token = process.env.GITHUB_TOKEN ?? '';\napp.listen(Number(process.env.PORT ?? 3000));\nexport const id = 'a3f5c2d1-7b9e-4c1a-8d2f-0e6b5a4c3d2e';\n",
        ),
        (
            "src/util.js",
            "const crypto = require('crypto');\nmodule.exports.hash = (s) => crypto.createHash('sha256').update(s).digest('hex');\n// sha256 of empty: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n",
        ),
        (
            "app/main.py",
            "import os\nimport hashlib\nAPI_KEY = os.environ['API_KEY']\npassword = os.getenv('DB_PASSWORD', '')\nSECRET_KEY_BASE = 'change-me'\nprint(hashlib.md5(b'x').hexdigest())\n",
        ),
        (
            "src/lib.rs",
            "use std::env;\nfn token() -> Option<String> { env::var(\"AWS_SECRET_ACCESS_KEY\").ok() }\nconst AKIA_PREFIX: &str = \"AKIA\";\n#[test] fn t() { assert_eq!(\"sk_test_placeholder\", \"sk_test_placeholder\"); }\n",
        ),
        (
            "cmd/main.go",
            "package main\n\nimport \"os\"\n\nfunc main() { _ = os.Getenv(\"SLACK_BOT_TOKEN\") }\n",
        ),
        (
            "deploy/ci.yaml",
            "name: ci\non: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n    env:\n      NPM_TOKEN: ${{ secrets.NPM_TOKEN }}\n      GH: ${{ secrets.GITHUB_TOKEN }}\n    steps:\n      - uses: actions/checkout@v4\n",
        ),
        (
            "package-lock.json",
            "{\n  \"name\": \"x\",\n  \"lockfileVersion\": 3,\n  \"packages\": {\n    \"node_modules/left-pad\": {\n      \"version\": \"1.3.0\",\n      \"resolved\": \"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz\",\n      \"integrity\": \"sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy/aVx2HrNcqQGsdot8ghrjyrvMCoEA==\"\n    }\n  }\n}\n",
        ),
        (
            "Cargo.lock",
            "[[package]]\nname = \"serde\"\nversion = \"1.0.200\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"ddc6f9cc94d67c0e21aaf7eda3a010fd3af78ebf6e096aa6e2e13c79749cce4f\"\n",
        ),
        (
            "yarn.lock",
            "left-pad@^1.3.0:\n  version \"1.3.0\"\n  resolved \"https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz#5b8a3a7765dfe001261dde915589e782f8c94d1e\"\n",
        ),
        (
            "README.md",
            "# Demo\n\nSet `DATABASE_URL`, `STRIPE_SECRET_KEY` and `GITHUB_TOKEN` in your environment.\n\n```sh\nexport OPENAI_API_KEY=your-key-here\nnpm_config_registry=https://registry.npmjs.org\n```\n\nKeys look like `sk-...` or `ghp_xxxxxxxx`.\n",
        ),
        (
            ".env.example",
            "DATABASE_URL=postgres://user:password@localhost:5432/app\nSTRIPE_SECRET_KEY=sk_test_xxx\nGITHUB_TOKEN=\nAWS_ACCESS_KEY_ID=AKIAXXXXXXXXXXXXXXXX\nSLACK_TOKEN=xoxb-your-token\n",
        ),
        (
            "docs/cert.pem.md",
            "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n",
        ),
    ];
    for (p, b) in files {
        r.write(p, b);
    }
    let o = scan(&h, &r, &[]);
    let hits = s(&o.stdout).lines().count();
    assert_eq!(hits, 0, "false positives:\n{}", s(&o.stdout));
    assert_eq!(o.status.code(), Some(0));
}
