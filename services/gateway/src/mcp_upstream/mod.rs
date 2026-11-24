//! M2 MCP gateway: the upstream hop (`/mcp/upstream/{name}`).
//!
//! Task 2.1 spike only: this module proves the rmcp client transport runs over the gateway's own
//! pinned HTTP client (`http_client.rs`: no redirects, no env proxy, pinned addresses). The proxy
//! itself arrives with tasks 2.2 to 2.4.

#[cfg(test)]
mod spike_tests {
    use rmcp::transport::StreamableHttpClientTransport;
    use rmcp::transport::streamable_http_client::{
        StreamableHttpClient, StreamableHttpClientTransportConfig,
    };
    use std::time::Duration;

    fn assert_client<C: StreamableHttpClient>(_: &C) {}

    /// The client `http_client::build` returns is accepted as the rmcp Streamable HTTP client
    /// (no second HTTP stack), and a transport can be built over it with a per-request credential.
    #[tokio::test]
    async fn rmcp_transport_runs_over_the_gateway_client() {
        let client =
            crate::http_client::build(Duration::from_secs(5), Duration::from_secs(60), None)
                .expect("client");
        assert_client(&client);
        let config = StreamableHttpClientTransportConfig::with_uri("https://upstream.example/mcp")
            .auth_header("not-a-real-token");
        let _transport = StreamableHttpClientTransport::with_client(client, config);
    }
}
