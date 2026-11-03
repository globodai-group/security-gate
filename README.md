# Security gate

Composite GitHub Action that blocks deployment when OSV reports a known
`CRITICAL` or `HIGH` vulnerability. It uses the advisory's
`database_specific.severity`; every `MAL-*` advisory is `CRITICAL`.
`MODERATE`, `LOW`, and unknown severities are reported but do not block.

## Use

Pin the action reference to an immutable commit SHA in consuming workflows.

```yaml
- uses: globodai-group/security-gate@<commit-sha>
  with:
    mode: deps
    path: .
    config: .security-gate.toml
```

`deps` is the default. It recursively runs `osv-scanner scan source` and
covers lockfiles osv-scanner supports, including npm, pnpm, yarn, bun,
Composer, pip/Poetry/uv, Bundler, pub, Go, and Cargo.

For a built local Docker image:

```yaml
- uses: globodai-group/security-gate@<commit-sha>
  with:
    mode: image
    image: local/service:build
```

`image` mode runs `osv-scanner scan image`, covering OS packages and software
bundled in the image. `image` is required in this mode. osv-scanner v2.7.0
reads npm packages in an image only from `node_modules/.package-lock.json`,
which bun and pnpm never write, so the Action also streams `docker export` of
the image, lists every `node_modules/<name>/package.json` (scoped and nested
included), and gates them as a synthesized npm lockfile. The log line
`security-gate: listed N npm packages` shows how many were found; an image
without `node_modules` skips this scan. Packages that bun and pnpm hardlink from
their store are resolved, and npm's own bundled packages in `node` base images
are gated too. A truncated or corrupt image stream fails the gate.

## Temporary exceptions

`.security-gate.toml` is optional and resolved from repository root. Every
ignore needs all fields. Expired ignores warn and no longer apply; an expiry
more than 90 days ahead is rejected. Unfixed `HIGH` and `CRITICAL` findings
still block unless covered by a current documented ignore. `MAL-*` advisories
cannot be ignored and always block; remove the malicious package.

```toml
[[ignore]]
id = "GHSA-xxxx"
reason = "why it cannot be fixed or is not reachable"
until = "2026-12-01"
```

The Action appends every finding to `$GITHUB_STEP_SUMMARY`, including ignored
and non-blocking findings, and emits one error annotation for each blocker.
Scanner download, scan, and OSV API errors fail closed.

## Pinned scanner

The Action downloads [osv-scanner v2.7.0](https://github.com/google/osv-scanner/releases/tag/v2.7.0)
for `linux_amd64`, verifies SHA-256
`160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b`,
then installs it in `$RUNNER_TEMP`. It never uses `go install` or a runtime
`latest` reference.
