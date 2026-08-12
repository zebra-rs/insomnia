fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Vendored copies of zebra-rs's machine-facing APIs (see proto/):
    // running-config subscription and the external show provider.
    tonic_prost_build::compile_protos("proto/config.proto")?;
    tonic_prost_build::compile_protos("proto/show.proto")?;
    Ok(())
}
