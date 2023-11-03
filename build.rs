// Example custom build script.
fn main() {
    println!("cargo:rerun-if-changed=scripts/generate-certs.sh");
    std::process::Command::new("bash").current_dir("scripts/").arg("generate-certs.sh").output().expect("Unable to generate certs!");
}