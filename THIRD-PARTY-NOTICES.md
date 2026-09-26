# Aether Third-Party Notices

Aether uses third-party open-source software.

The third-party dependencies below are not owned by the Aether project. Their respective licenses and notices continue to apply.

Aether does not vendor or copy these dependency source trees into the repository.

## Dependencies identified by `go-licenses report ./...`

| Dependency                                         | License      |
| -------------------------------------------------- | ------------ |
| `github.com/Microsoft/go-winio` v0.6.2             | MIT          |
| `github.com/go-jose/go-jose/v4` v4.1.4             | Apache-2.0   |
| `github.com/go-jose/go-jose/v4/json`               | BSD-3-Clause |
| `github.com/spiffe/go-spiffe/v2` v2.8.1            | Apache-2.0   |
| `golang.org/x/net` v0.48.0                         | BSD-3-Clause |
| `golang.org/x/sys/windows` v0.39.0                 | BSD-3-Clause |
| `golang.org/x/text` v0.32.0                        | BSD-3-Clause |
| `google.golang.org/genproto/googleapis/rpc/status` | Apache-2.0   |
| `google.golang.org/grpc` v1.79.3                   | Apache-2.0   |
| `google.golang.org/protobuf` v1.36.11              | BSD-3-Clause |

## Upstream License Sources

The current audit identified these upstream license sources:

* `github.com/Microsoft/go-winio` â€” https://github.com/Microsoft/go-winio/blob/v0.6.2/LICENSE
* `github.com/go-jose/go-jose/v4` â€” https://github.com/go-jose/go-jose/blob/v4.1.4/LICENSE
* `github.com/go-jose/go-jose/v4/json` â€” license distributed with the `json` subpackage
* `github.com/spiffe/go-spiffe/v2` â€” https://github.com/spiffe/go-spiffe/blob/v2.8.1/LICENSE
* `golang.org/x/net` â€” https://cs.opensource.google/go/x/net/+/v0.48.0:LICENSE
* `golang.org/x/sys` â€” https://cs.opensource.google/go/x/sys/+/v0.48.0:LICENSE
* `golang.org/x/text` â€” https://cs.opensource.google/go/x/text/+/v0.32.0:LICENSE
* `google.golang.org/genproto` â€” https://github.com/googleapis/go-genproto
* `google.golang.org/grpc` â€” https://github.com/grpc/grpc-go/blob/v1.79.3/LICENSE
* `google.golang.org/protobuf` â€” https://github.com/protocolbuffers/protobuf-go/blob/v1.36.11/LICENSE

## Aether License Boundary

The Apache License 2.0 in the Aether repository applies to Aether software to which that license is expressly applied.

It does not replace the licenses of third-party dependencies.

Third-party copyrights, trademarks, notices, and license conditions remain with their respective owners.

## Audit Method

The dependency report was generated from the repository with:

```powershell
go-licenses report ./...
```

The audit was performed against the current build dependency graph.

The local Aether module itself was reported by `go-licenses` as `Unknown` for its source URL because `aether-protocol` is a local module name. The repository separately contains the official Apache License 2.0 text in `LICENSE`.

## Distribution Note

Before a public release, dependency notices should be re-generated from the final release candidate so that the notice remains synchronized with the actual dependency graph used by that release.
