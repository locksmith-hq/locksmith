fn main() {
    let commit = std::process::Command::new("git")
        .args(["rev-parse", "--short=9", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".into());
    println!("cargo:rustc-env=SMITH_COMMIT={commit}");
    println!(
        "cargo:rustc-env=SMITH_TARGET={}",
        std::env::var("TARGET").unwrap()
    );
    println!(
        "cargo:rustc-env=SMITH_CHANNEL={}",
        std::env::var("LOCKSMITH_CHANNEL").unwrap_or_else(|_| "dev".into())
    );
    println!("cargo:rerun-if-env-changed=LOCKSMITH_CHANNEL");
    println!("cargo:rerun-if-changed=../../.git/HEAD");
}
