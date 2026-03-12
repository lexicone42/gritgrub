fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
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
