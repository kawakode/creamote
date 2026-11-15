//! Compile les schémas `proto/` sans dépendre d'un `protoc` installé
//! (compilateur protobuf pur Rust : protox).

use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../proto");
    let files = [
        "creamote/common.proto",
        "creamote/rendezvous.proto",
        "creamote/session.proto",
    ];
    for f in &files {
        println!("cargo:rerun-if-changed={}", root.join(f).display());
    }
    let fds = protox::compile(files, [&root])?;
    prost_build::Config::new().compile_fds(fds)?;
    Ok(())
}
