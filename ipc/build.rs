use std::io::Result;

fn main() -> Result<()> {
    std::env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path().unwrap());
    // The status snapshot grows independently of the small event/command cases.
    // Box only this Rust oneof variant; protobuf bytes and C# types are unchanged.
    prost_build::Config::new()
        .boxed(".vpnclient.status.StatusMessage.body.snapshot")
        .compile_protos(&["proto/policy.proto", "proto/status.proto"], &["proto"])?;
    println!("cargo:rerun-if-changed=proto/policy.proto");
    println!("cargo:rerun-if-changed=proto/status.proto");
    Ok(())
}
