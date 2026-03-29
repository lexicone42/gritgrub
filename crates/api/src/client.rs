//! gRPC client for push/pull/clone operations.

use anyhow::{bail, Result};
use tonic::transport::Channel;
use tonic::metadata::MetadataValue;
use crate::pb;
use crate::pb::repo_service_client::RepoServiceClient;
use gritgrub_core::*;
use gritgrub_store::Repository;

type InterceptedClient = RepoServiceClient<
    tonic::service::interceptor::InterceptedService<
        Channel,
        Box<dyn Fn(tonic::Request<()>) -> std::result::Result<tonic::Request<()>, tonic::Status> + Send + Sync>,
    >,
>;

pub struct ForgeClient {
    client: InterceptedClient,
}

impl ForgeClient {
    /// Connect to a remote forge server.
    /// URLs without a scheme default to https://.
    pub async fn connect(url: &str, token: Option<&str>) -> Result<Self> {
        let url = normalize_url(url);
        let mut endpoint = Channel::from_shared(url.clone())?;

        // Enable TLS for https:// URLs using system trust store (mkcert CA, etc.)
        if url.starts_with("https://") {
            let mut tls = tonic::transport::ClientTlsConfig::new()
                .with_native_roots();

            // When connecting to an IP address, override the TLS domain name
            // to "localhost" since IP addresses can't be used for SNI.
            if let Some(host) = extract_host(&url) {
                if is_ip_address(&host) {
                    tls = tls.domain_name("localhost");
                }
            }
            endpoint = endpoint.tls_config(tls)?;
        }

        let channel = endpoint.connect().await?;

        let token_owned = token.map(|t| t.to_string());
        let interceptor: Box<dyn Fn(tonic::Request<()>) -> std::result::Result<tonic::Request<()>, tonic::Status> + Send + Sync> =
            if let Some(tok) = token_owned {
                let token_val: MetadataValue<_> = format!("Bearer {}", tok).parse()
                    .map_err(|_| anyhow::anyhow!("invalid token"))?;
                Box::new(move |mut req: tonic::Request<()>| {
                    req.metadata_mut().insert("authorization", token_val.clone());
                    Ok(req)
                })
            } else {
                Box::new(|req: tonic::Request<()>| Ok(req))
            };

        let client = RepoServiceClient::with_interceptor(channel, interceptor);
        Ok(Self { client })
    }

    /// Push local objects and update remote refs.
    /// Walks the changeset graph from `local_ref` and sends all objects
    /// the remote doesn't have, then CAS-updates the remote ref.
    pub async fn push(
        &mut self,
        repo: &Repository,
        local_ref: &str,
        remote_ref: &str,
    ) -> Result<()> {
        // 1. Resolve local ref.
        let local_id = repo.resolve_ref(local_ref)?
            .ok_or_else(|| anyhow::anyhow!("local ref '{}' not found", local_ref))?;

        // 2. Negotiate — find out what the remote already has.
        let negotiate_resp = self.client
            .negotiate_refs(pb::NegotiateRefsRequest { client_refs: vec![] })
            .await?
            .into_inner();

        let remote_tip = negotiate_resp.server_refs.iter()
            .find(|r| r.name == remote_ref)
            .and_then(|r| r.value.as_ref())
            .and_then(|v| v.value.as_ref())
            .and_then(|v| match v {
                pb::ref_value::Value::Direct(id) => from_pb_id(id).ok(),
                _ => None,
            });

        // 3. Collect objects to send — walk from local_id, stop at remote_tip.
        let mut to_send = Vec::new();
        let mut queue = std::collections::VecDeque::new();
        let mut seen = std::collections::HashSet::new();
        queue.push_back(local_id);

        while let Some(id) = queue.pop_front() {
            if !seen.insert(id) {
                continue;
            }
            if Some(id) == remote_tip {
                continue; // Remote already has this and its ancestors.
            }

            if let Some(obj) = repo.get_object(&id)? {
                if let Object::Changeset(ref cs) = obj {
                    for p in &cs.parents {
                        queue.push_back(*p);
                    }
                    queue.push_back(cs.tree);
                }
                if let Object::Tree(ref tree) = obj {
                    for entry in tree.entries.values() {
                        queue.push_back(entry.id);
                    }
                }
                to_send.push(obj.to_tagged_bytes());
            }
        }

        // 4. Stream objects to remote.
        if !to_send.is_empty() {
            let stream = tokio_stream::iter(
                to_send.into_iter().map(|data| pb::PushObjectChunk { data })
            );
            let resp = self.client.push_objects(stream).await?.into_inner();
            eprintln!("Pushed {} objects", resp.received);
        }

        // 5. CAS-update the remote ref.
        let expected = remote_tip.map(|id| pb::RefValue {
            value: Some(pb::ref_value::Value::Direct(to_pb_id(&id))),
        });
        let new_value = Some(pb::RefValue {
            value: Some(pb::ref_value::Value::Direct(to_pb_id(&local_id))),
        });

        let cas_resp = self.client.cas_ref(pb::CasRefRequest {
            name: remote_ref.to_string(),
            expected,
            new_value,
        }).await?.into_inner();

        if !cas_resp.success {
            bail!("push rejected: remote ref was updated by another agent (CAS failed). Pull and retry.");
        }

        Ok(())
    }

    /// Pull remote objects and update local refs.
    pub async fn pull(
        &mut self,
        repo: &Repository,
        remote_ref: &str,
        local_ref: &str,
    ) -> Result<ObjectId> {
        // 1. Get remote ref value.
        let ref_resp = self.client.get_ref(pb::GetRefRequest {
            name: remote_ref.to_string(),
        }).await?.into_inner();

        let remote_id = ref_resp.resolved
            .as_ref()
            .and_then(|id| from_pb_id(id).ok())
            .ok_or_else(|| anyhow::anyhow!("remote ref '{}' not found", remote_ref))?;

        // 2. Build "have" list from local state.
        let mut have = Vec::new();
        if let Some(local_id) = repo.resolve_ref(local_ref)? {
            have.push(to_pb_id(&local_id));
        }

        // 3. Fetch objects.
        let mut stream = self.client.fetch_objects(pb::FetchObjectsRequest {
            want: vec![to_pb_id(&remote_id)],
            have,
        }).await?.into_inner();

        let mut count = 0u32;
        while let Some(chunk) = tokio_stream::StreamExt::next(&mut stream).await {
            let chunk = chunk?;
            let obj = Object::from_tagged_bytes(&chunk.data)?;
            repo.put_object(&obj)?;
            count += 1;
        }
        if count > 0 {
            eprintln!("Received {} objects", count);
        }

        // 4. Update local ref.
        repo.set_ref(local_ref, &Ref::Direct(remote_id))?;

        Ok(remote_id)
    }

    /// Clone: init a new repo and pull all refs from remote.
    pub async fn clone_repo(
        url: &str,
        path: &std::path::Path,
        token: Option<&str>,
    ) -> Result<()> {
        let repo = Repository::init(path)?;
        let mut client = Self::connect(url, token).await?;

        // Get all remote refs.
        let negotiate_resp = client.client
            .negotiate_refs(pb::NegotiateRefsRequest { client_refs: vec![] })
            .await?
            .into_inner();

        // Find the main branch or first available.
        let main_ref = negotiate_resp.server_refs.iter()
            .find(|r| r.name == "refs/heads/main")
            .or_else(|| negotiate_resp.server_refs.iter()
                .find(|r| r.name.starts_with("refs/heads/")));

        if let Some(main) = main_ref {
            let remote_ref = &main.name;
            let remote_id = client.pull(&repo, remote_ref, remote_ref).await?;

            // Checkout the working tree (force — HEAD was just updated).
            if let Some(Object::Changeset(cs)) = repo.get_object(&remote_id)? {
                repo.force_checkout_tree(&cs.tree)?;
            }
            eprintln!("Cloned at {}", remote_id);
        } else {
            eprintln!("Remote has no branches — empty clone.");
        }

        // Store the remote URL.
        repo.add_remote("origin", url)?;

        Ok(())
    }
}

// ── Helpers ─────────────────────────────────────────────────────────

fn to_pb_id(id: &ObjectId) -> pb::ObjectId {
    pb::ObjectId { hash: id.as_bytes().to_vec() }
}

fn from_pb_id(pb_id: &pb::ObjectId) -> Result<ObjectId> {
    let bytes: [u8; 32] = pb_id.hash.as_slice().try_into()
        .map_err(|_| anyhow::anyhow!("ObjectId must be 32 bytes"))?;
    Ok(ObjectId::from_bytes(bytes))
}

/// Normalize a server URL: default to https:// if no scheme is given.
/// Allows explicit http:// for testing/CI (opt-in insecure).
fn normalize_url(url: &str) -> String {
    if url.starts_with("http://") || url.starts_with("https://") {
        url.to_string()
    } else {
        format!("https://{}", url)
    }
}

/// Extract host from a URL like "https://[::1]:50051" → "::1" or "https://localhost:50051" → "localhost".
fn extract_host(url: &str) -> Option<String> {
    let without_scheme = url.strip_prefix("https://").or_else(|| url.strip_prefix("http://"))?;
    // IPv6 bracket notation: [::1]:port
    if let Some(bracket_end) = without_scheme.find(']') {
        return Some(without_scheme[1..bracket_end].to_string());
    }
    // host:port or just host
    Some(without_scheme.split(':').next()?.to_string())
}

/// Check if a string is an IP address (v4 or v6).
fn is_ip_address(host: &str) -> bool {
    host.parse::<std::net::IpAddr>().is_ok()
}
