//! Compile the vendored CRI v1 proto (`runtime.v1`) into tonic server + client
//! bindings. Uses the tonic 0.14 split-crate codegen (`tonic-prost-build`).

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=../../proto/runtime/v1/api.proto");
    // Point prost/tonic at a vendored protoc unless the environment already
    // provides one, so the build works without a system protobuf-compiler
    // (CI runners don't ship one; keeps local == CI).
    if std::env::var_os("PROTOC").is_none() {
        std::env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path()?);
    }
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&["../../proto/runtime/v1/api.proto"], &["../../proto"])?;
    Ok(())
}
