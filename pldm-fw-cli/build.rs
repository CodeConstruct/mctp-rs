use std::process::Command;

fn main() {
    let version = Command::new("git")
                   .args(["describe", "--always", "--tags", "--dirty"])
                   .output()
                   .map(|o| String::from_utf8(o.stdout).unwrap().to_string())
                   .unwrap_or("(unknown)".to_string());

    println!("cargo:rustc-env=VERSION={version}");
    println!("cargo:rerun-if-changed=.git/HEAD");
}
