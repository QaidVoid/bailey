//! Build script.
//!
//! When the `ebpf` feature is enabled, compiles the `bailey-ebpf` crate for the
//! BPF target with aya-build and places the object in `OUT_DIR` for the audit
//! backend to embed. Without the feature this is a no-op, so a default build
//! needs neither a nightly toolchain nor bpf-linker.

fn main() {
    if std::env::var_os("CARGO_FEATURE_EBPF").is_none() {
        return;
    }

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
