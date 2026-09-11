# REST API (OpenAPI)

The full machine-readable specification lives at
[`specs/openapi.yaml`](../../../specs/openapi.yaml).

This REST API covers supplementary endpoints not available via JSON-RPC —
primarily DID resolution, node status queries, and admin operations.

## Base URL

```
http://127.0.0.1:8547
```

## Related

- [JSON-RPC 2.0](json-rpc.md) — primary transaction submission endpoint
- [Protobuf / gRPC](grpc.md) — high-performance native client path
