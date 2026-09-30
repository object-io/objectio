fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Compile protobuf definitions
    tonic_build::configure()
        // Shard payloads as `Bytes`, so a shard can be handed to gRPC without
        // copying it and a received one is a view into the receive buffer.
        .bytes([
            ".objectio.storage.WriteShardRequest.data",
            ".objectio.storage.ReadShardResponse.data",
        ])
        .build_server(true)
        .build_client(true)
        .compile_protos(
            &[
                "proto/storage.proto",
                "proto/metadata.proto",
                "proto/cluster.proto",
                "proto/block.proto",
                "proto/raft.proto",
            ],
            &["proto"],
        )?;

    Ok(())
}
