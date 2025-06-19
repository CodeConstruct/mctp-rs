use std::process::Command;

fn main() {
    let version = Command::new("git")
        .args(["describe", "--always", "--dirty"])
        .output()
        .map(|o| String::from_utf8(o.stdout).unwrap().trim().to_string())
        .unwrap_or("(unknown)".to_string());

    let path_res = Command::new("git")
        .args(["rev-parse", "--path-format=relative", "--git-dir"])
        .output()
        .map(|o| String::from_utf8(o.stdout).unwrap().trim().to_string());

    println!("cargo:rustc-env=VERSION={version}");
    if let Ok(path) = path_res {
        println!("cargo:rerun-if-changed={path}/HEAD");
        // default rerun paths get lost once any have been added.
        println!("cargo:rerun-if-changed=.");
    }
}
