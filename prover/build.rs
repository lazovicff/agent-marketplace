//! Build script that compiles the SP1 zkVM program using `cargo prove build`.
//! The resulting ELF binary is embedded into the prover binary.

use std::process::Command;

fn main() {
    let program_dir = format!("{}/program", env!("CARGO_MANIFEST_DIR"));

    // Use cargo prove build to compile the SP1 program
    let status = Command::new("cargo")
        .args(["prove", "build"])
        .current_dir(&program_dir)
        .status()
        .expect("Failed to run cargo prove build. Is sp1up installed?");

    if !status.success() {
        panic!("cargo prove build failed");
    }

    // The ELF is placed in the target/elf-compilation directory.
    // We need to find it and set the environment variable for include_elf!.
    let target_dir = format!(
        "{}/../target/elf-compilation/riscv64im-succinct-zkvm-elf/release/zk-tls-program",
        env!("CARGO_MANIFEST_DIR")
    );

    // Check if the ELF exists at the expected path
    if std::path::Path::new(&target_dir).exists() {
        println!("cargo:rustc-env=SP1_ELF_zk-tls-program={}", target_dir);
    } else {
        // Try alternative path (riscv32im)
        let alt_target_dir = format!(
            "{}/../target/elf-compilation/riscv32im-succinct-zkvm-elf/release/zk-tls-program",
            env!("CARGO_MANIFEST_DIR")
        );
        if std::path::Path::new(&alt_target_dir).exists() {
            println!("cargo:rustc-env=SP1_ELF_zk-tls-program={}", alt_target_dir);
        } else {
            panic!("ELF not found at {} or {}", target_dir, alt_target_dir);
        }
    }
}
