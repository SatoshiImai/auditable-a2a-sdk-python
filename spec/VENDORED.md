# Vendored spec artifacts — DO NOT EDIT BY HAND

The files under `schema/` and `vectors/` are **vendored copies** of the normative Auditable A2A spec
artifacts. Their single source of truth is the `auditable-a2a` repository (`spec/schema/`,
`spec/vectors/`), generated there from the TypeScript Zod reference (`reference/typescript`).

They are copied here so this SDK builds, tests, and publishes standalone, and they are byte-identical
to the TypeScript SDK's copy so both languages reproduce the same vectors.

## Updating

```bash
make spec/sync     # re-copy from ../auditable-a2a/spec
make spec/check    # verify no drift
```

Point at a spec checkout elsewhere with `--source <path>` or `AA2A_SPEC_SRC=<path>`.

## Why vendored, not edited

The extension is `auditable-a2a/0.1`, over `auditable-mcp/0.4`. A conforming implementation reproduces
every vector (spec §12). Editing these files here would fork the contract; fix the spec upstream and
re-sync instead.
