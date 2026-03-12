fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR")?);

    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        // Emit file descriptor set for gRPC reflection.
        .file_descriptor_set_path(out_dir.join("gritgrub_descriptor.bin"))
        .compile_protos(
            &[
                "../../proto/gritgrub/v1/objects.proto",
                "../../proto/gritgrub/v1/identity.proto",
                "../../proto/gritgrub/v1/repo.proto",
                "../../proto/gritgrub/v1/events.proto",
                "../../proto/gritgrub/v1/attestation.proto",
            ],
            &["../../proto"],
        )?;
    Ok(())
}
