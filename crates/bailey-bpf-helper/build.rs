//! Build script: compiles the `bailey-ebpf` programs for the BPF target with
//! aya-build and places the object in `OUT_DIR` for the helper to embed.
//! Requires a nightly toolchain and bpf-linker.

fn main() {
    let ebpf_dir = format!("{}/../bailey-ebpf", env!("CARGO_MANIFEST_DIR"));
    aya_build::build_ebpf(
        [aya_build::Package {
            name: "bailey-ebpf",
            root_dir: &ebpf_dir,
            no_default_features: false,
            features: &[],
        }],
        aya_build::Toolchain::Custom("nightly"),
    )
    .expect("failed to build bailey-ebpf");

    println!("cargo:rerun-if-changed={ebpf_dir}/src");
    println!("cargo:rerun-if-changed={ebpf_dir}/Cargo.toml");
}
