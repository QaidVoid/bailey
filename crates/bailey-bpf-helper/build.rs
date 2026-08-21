//! Build script: compiles the `bailey-ebpf` programs for the BPF target with
//! aya-build and places the object in `OUT_DIR` for the helper to embed.
//! Requires a nightly toolchain and bpf-linker.
//!
//! The `bpf` feature is what makes the program compile at all. It is off by
//! default so that whole-workspace commands skip a crate that only links for the
//! BPF target; enabling it here is the only place it is ever on.

fn main() {
    let ebpf_dir = format!("{}/../bailey-ebpf", env!("CARGO_MANIFEST_DIR"));
    if let Err(err) = aya_build::build_ebpf(
        [aya_build::Package {
            name: "bailey-ebpf",
            root_dir: &ebpf_dir,
            no_default_features: false,
            features: &["bpf"],
        }],
        aya_build::Toolchain::Custom("nightly"),
    ) {
        // The usual cause is a missing toolchain rather than anything wrong with
        // the code, and the underlying error does not say so.
        panic!(
            "could not build the eBPF programs: {err}\n\
             This needs a nightly toolchain and bpf-linker:\n\
             \x20 rustup toolchain install nightly\n\
             \x20 rustup component add rust-src --toolchain nightly\n\
             \x20 cargo install bpf-linker\n\
             Only `bailey audit` needs this crate; the sandbox itself builds \
             with stable and no system dependencies."
        );
    }

    println!("cargo:rerun-if-changed={ebpf_dir}/src");
    println!("cargo:rerun-if-changed={ebpf_dir}/Cargo.toml");
}
