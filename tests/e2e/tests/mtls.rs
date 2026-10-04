//! mTLS between the services (A8a): a node accepts gRPC only from peers
//! presenting a certificate the cluster's CA signed.

use objectio_e2e::ha::HaCluster;
use objectio_proto::metadata::GetMetricsRequest;
use objectio_proto::metadata::metadata_service_client::MetadataServiceClient;
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint, Identity};

/// A call refused at the connection, not answered by meta.
fn refused(r: Result<(), String>) -> bool {
    r.is_err_and(|e| !e.contains("FailedPrecondition") && !e.contains("PermissionDenied"))
}

/// What a call to meta, connected as `ep` describes, gets.
fn call(rt: &tokio::runtime::Runtime, ep: Result<Endpoint, String>) -> Result<(), String> {
    rt.block_on(async {
        // As the current release: meta refuses a client too old for the
        // cluster, which would look like a refusal for another reason.
        let channel = ep?
            .user_agent(objectio_common::version::user_agent())
            .map_err(|e| e.to_string())?
            .connect()
            .await
            .map_err(|e| e.to_string())?;
        MetadataServiceClient::new(channel)
            .get_metrics(GetMetricsRequest::default())
            .await
            .map(drop)
            .map_err(|e| e.to_string())
    })
}

#[test]
fn a_node_refuses_a_client_without_the_clusters_certificate() {
    let Some(files) = objectio_e2e::tls::files() else {
        return; // the suite runs plain: nothing to refuse
    };
    let ha = HaCluster::start(1, 6, 1);
    let addr = ha
        .meta_endpoints()
        .trim_start_matches("http://")
        .to_string();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let pem = |p: &std::path::Path| std::fs::read(p).unwrap();

    // Plain gRPC.
    let plain = Endpoint::from_shared(format!("http://{addr}")).map_err(|e| e.to_string());
    assert!(refused(call(&rt, plain)), "a plaintext client was served");

    // TLS, trusting the CA, but no certificate of its own.
    let anonymous = Endpoint::from_shared(format!("https://{addr}"))
        .and_then(|e| {
            e.tls_config(
                ClientTlsConfig::new().ca_certificate(Certificate::from_pem(pem(&files.ca))),
            )
        })
        .map_err(|e| e.to_string());
    assert!(
        refused(call(&rt, anonymous)),
        "a client with no certificate was served"
    );

    // A certificate another CA signed.
    let other = {
        use rcgen::{CertificateParams, KeyPair};
        let key = KeyPair::generate().unwrap();
        let cert = CertificateParams::new(vec!["127.0.0.1".to_string()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        Identity::from_pem(cert.pem(), key.serialize_pem())
    };
    let stranger = Endpoint::from_shared(format!("https://{addr}"))
        .and_then(|e| {
            e.tls_config(
                ClientTlsConfig::new()
                    .ca_certificate(Certificate::from_pem(pem(&files.ca)))
                    .identity(other),
            )
        })
        .map_err(|e| e.to_string());
    assert!(
        refused(call(&rt, stranger)),
        "a client with another CA's certificate was served"
    );

    // The cluster's certificate: served.
    objectio_e2e::tls::client();
    call(&rt, objectio_proto::transport::endpoint(&addr)).expect("the cluster's own certificate");
}
