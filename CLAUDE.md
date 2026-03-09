# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository. Always create a new git branch before making changes. Branch names should follow the pattern feature/<short-description>. Changes should include updates to README.md whenever the public API changes, and updates to CLAUDE.md whenever there is a structural change. Always check ALL unit tests after making changes.

## Project Overview

SwiftLDAP is a pure-Swift LDAPv3 client library with async/await support. Zero external dependencies — built on Foundation and Darwin/CoreFoundation only. Targets macOS 13+ / iOS 16+ (Darwin-only due to CFStream-based transport). Uses Swift 6.0 strict concurrency throughout.

Implements RFC 4511 (LDAPv3), RFC 4513 (auth/TLS), RFC 4515 (filter strings), RFC 4512 (rootDSE/server info), RFC 4532 (Who Am I?).

## Build & Test Commands

```bash
swift build                              # Build the library
swift test                               # Run unit tests only
swift test --filter SwiftLDAPTests       # Run unit tests explicitly
swift test --filter SwiftLDAPTests.<SuiteName>  # Run a specific test suite (e.g. BEREncoderTests)

# Integration tests (require Docker)
./scripts/integration-tests.sh           # Full cycle: generate certs, start OpenLDAP, run tests, tear down
./scripts/integration-tests.sh --keep    # Keep container running after tests

# Manual integration test workflow
bash scripts/generate-test-certs.sh
docker compose up -d --wait
LDAP_INTEGRATION_TESTS=1 swift test --filter IntegrationTests
docker compose down -v
```

## Architecture

### Layered Design (bottom-up)

1. **Transport** (`Sources/SwiftLDAP/Transport/`) — `StreamTransport` (private) wraps POSIX sockets + CFStream for TCP I/O with TLS support. `LDAPConnection` (internal actor) frames complete BER messages from the raw byte stream. `LDAPSecurityMode` enum defines `.none`, `.startTLS`, `.ldaps`. `LDAPConnectionConfig` (public struct) exposes configurable limits: `connectTimeout`, `operationTimeout`, `maxMessageSize` (10 MB default), `maxSearchEntries`, and `tlsVerifyPeer`.

2. **BER** (`Sources/SwiftLDAP/BER/`) — ASN.1 BER encoding/decoding. `BEREncoder` builds TLV byte arrays via a closure-based sub-encoder pattern for constructed types. `BERDecoder` reads TLV elements sequentially from a byte slice. `ASN1Tag` defines all universal and LDAP application-specific tags.

3. **Protocol** (`Sources/SwiftLDAP/Protocol/`) — `LDAPCodec` translates between `LDAPOperation` enum (21 cases for all request/response PDUs) and BER bytes. `LDAPFilter` is an indirect enum with BER encode/decode and an RFC 4515 recursive-descent string parser; convenience constructors include `.equal(attr, value)`, `.exists(attr)`, `.substring(attr, pattern)`. `LDAPResultCode` covers all 37 RFC 4511 codes. `LDAPMessage.swift` defines shared protocol structures: `LDAPControl`, `ModifyItem`, `SearchParameters`, `BindAuthentication`, `SearchScope`, `DerefAliases`, `ModifyOperation`.

4. **Models** (`Sources/SwiftLDAP/Models/`) — `LDAPEntry` (dn + `[String: [Data]]` attributes), `LDAPAttribute`, `LDAPError` (8-case enum covering server errors, TLS, protocol, timeout, I/O), `LDAPServerFingerprint` (rootDSE-derived server info), `LDAPServerType` enum (`.openLDAP`, `.activeDirectory`, `.directoryServer389`, `.apacheDS`, `.unknown`).

5. **Client** (`LDAPClient.swift`) — The sole public entry point. An `actor` that allocates message IDs, encodes requests via `LDAPCodec`, sends/receives via `LDAPConnection`, decodes responses, and returns typed results. Operations: `connect`, `simpleBind`, `search`, `searchStream`, `add`, `modify`, `delete`, `modifyDN`, `compare`, `whoAmI`, `extendedOperation`, `fingerprint`.

### Key Patterns

- **Actor isolation**: `LDAPClient` (public) and `LDAPConnection` (internal) are actors. `StreamTransport` is `@unchecked Sendable` with serial DispatchQueues for read/write.
- **Message framing**: `LDAPConnection.receiveMessage()` accumulates bytes until a complete BER TLV is available, handling multi-chunk reads.
- **Streaming search**: `searchStream()` returns `AsyncThrowingStream<LDAPEntry, Error>` for memory-efficient large result sets.

## Testing

- **Unit tests** (`Tests/SwiftLDAPTests/`) use Swift Testing framework (`@Suite`, `@Test`). All pure in-memory, no network.
- **Integration tests** (`Tests/IntegrationTests/`) are gated by the `LDAP_INTEGRATION_TESTS` env var. Tests use `.enabled(if: integrationEnabled)`. All suites are `.serialized` to avoid concurrent mutations against the shared OpenLDAP instance.
- **Test data**: `Tests/IntegrationTests/Fixtures/seed.ldif` seeds `dc=example,dc=org` with users and groups.
- Integration test env vars: `LDAP_TEST_HOST` (default `localhost`), `LDAP_TEST_PORT` (default `1389`), `LDAP_TEST_LDAPS_PORT` (default `1636`).
