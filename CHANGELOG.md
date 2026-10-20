# Changelog

Changes to the Auditable A2A Python SDK. A package version 0.X.Y implements the extension
`auditable-a2a/0.X`; Y counts the package's own fixes and dependency updates.

## 0.1.1 - 2026-10-20

- `A2aAuditHost.open_session` refuses a countersigning key whose id is not `{hostKeys}#{kid}` (§7.1, §10.2).
  A delegate resolves a receipt's `host_key_id` at `hostKeys`; a key named any other way is never found there,
  and every countersignature it made reads as `host-signature-invalid`. Found when an audit host named its key
  by the bare `kid` its own registry used.

## 0.1.0 - 2026-10-16

Initial release, implementing `auditable-a2a/0.1` over `auditable-mcp/0.4` through `auditable-mcp-sdk` 0.4,
with an optional binding to the official A2A Python SDK (`a2a-sdk` 1.2, the `a2a` extra). The TypeScript SDK's
0.1.0 implements the same release. See the README for what it covers.
