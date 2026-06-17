//! Compile the vendored CRI v1 proto (`runtime.v1`) into tonic server + client
//! bindings. Uses the tonic 0.14 split-crate codegen (`tonic-prost-build`).

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=../../proto/runtime/v1/api.proto");
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&["../../proto/runtime/v1/api.proto"], &["../../proto"])?;
    Ok(())
}
