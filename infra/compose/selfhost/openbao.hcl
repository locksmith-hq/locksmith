# OpenBao production mode for the self-host bundle: single node, on-disk storage. OpenBao 2.7.2 has no
# `file` backend ("unknown storage type file"), so this uses integrated raft storage with one node,
# which is the supported on-disk backend. The listener is
# plain HTTP on the compose network only (the port is not published); put TLS in front with the
# `tls` profile or an external OpenBao for anything beyond one host.
ui = false
api_addr = "http://openbao:8200"
cluster_addr = "http://127.0.0.1:8201"
# Service tokens made by openbao-entrypoint.sh live for ten years (no renewal job in this bundle).
max_lease_ttl = "87600h"

storage "raft" {
  path    = "/openbao/file"
  node_id = "locksmith-1"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true
}
