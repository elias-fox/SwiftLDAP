# DISCLAIMER

This is mostly vibe coded, with some manual changes from myself to handle certain issues.

My process was:

1. Direct the LLM to focus on implementing the actual spec (so Claude went and named dropped the RFCs whereever it could; I think it's showing off)
2. Once the initial package was completed, sanity check the unit tests to ensure they're testing what they claim and that they pass
3. Generate an integration test suite against an openldap instance for objective measurements (once again, sanity checks)

It's definitely over-commented and over-engineered, but it seems to work. Use at your own risk, but if you see an issue feel free to submit a PR.

EVERYTHING BELOW IS CLAUDE OPUS 4.6

# SwiftLDAP

A pure-Swift LDAPv3 client with async/await support. No external dependencies — built entirely on Foundation.

Implements [RFC 4511](https://datatracker.ietf.org/doc/html/rfc4511) (LDAPv3 protocol), [RFC 4513](https://datatracker.ietf.org/doc/html/rfc4513) (authentication), [RFC 4515](https://datatracker.ietf.org/doc/html/rfc4515) (search filter syntax), and [RFC 4532](https://datatracker.ietf.org/doc/html/rfc4532) (Who Am I?).

## Requirements

- Swift 6.0+
- macOS 13+ / iOS 16+

## Installation

Add SwiftLDAP to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/example/SwiftLDAP.git", from: "1.0.0"),
],
targets: [
    .target(
        name: "MyApp",
        dependencies: ["SwiftLDAP"]
    ),
]
```

## Quick Start

```swift
import SwiftLDAP

let client = LDAPClient(host: "ldap.example.com", security: .startTLS)
try await client.connect()
try await client.simpleBind(dn: "cn=admin,dc=example,dc=com", password: "secret")

let entries = try await client.search(
    baseDN: "dc=example,dc=com",
    filter: .equal("cn", "Jane Doe")
)

for entry in entries {
    print(entry.dn)
    print("  mail: \(entry.firstValue(for: "mail") ?? "n/a")")
}

try await client.unbind()
```

## Connecting

`LDAPClient` is an actor — all operations are concurrency-safe.

### Security Modes

| Mode | Default Port | Description |
|------|-------------|-------------|
| `.none` | 389 | Plain-text (no encryption) |
| `.startTLS` | 389 | Connects plain, upgrades to TLS before any credentials are sent |
| `.ldaps` | 636 | TLS from the start |

```swift
// LDAPS on the default port (636)
let client = LDAPClient(host: "ldap.example.com", security: .ldaps)

// StartTLS on a custom port
let client = LDAPClient(host: "ldap.example.com", port: 3389, security: .startTLS)

// Disable certificate verification (testing only)
let client = LDAPClient(host: "localhost", security: .ldaps, tlsVerifyPeer: false)
```

Call `connect()` to establish the TCP connection. For `.startTLS`, the TLS handshake is performed automatically before `connect()` returns.

```swift
try await client.connect()
```

### Using `LDAPConnectionConfig`

For more control, pass an `LDAPConnectionConfig` directly:

```swift
let config = LDAPConnectionConfig(
    host: "ldap.example.com",
    port: 636,
    security: .ldaps,
    tlsVerifyPeer: true,
    connectTimeout: 10,
    operationTimeout: 30
)
let client = LDAPClient(config: config)
try await client.connect()
```

## Authentication

### Simple Bind

```swift
try await client.simpleBind(
    dn: "cn=admin,dc=example,dc=com",
    password: "secret"
)
```

### Anonymous Bind

```swift
try await client.simpleBind()
```

### SASL Bind

```swift
let (result, serverCreds) = try await client.saslBind(
    mechanism: "EXTERNAL"
)
```

### Unbind

Sends an unbind notification and closes the connection:

```swift
try await client.unbind()
```

To close without notifying the server, use `disconnect()`:

```swift
await client.disconnect()
```

## Searching

### Basic Search

```swift
let entries = try await client.search(
    baseDN: "ou=people,dc=example,dc=com",
    scope: .wholeSubtree,
    filter: .equal("objectClass", "inetOrgPerson"),
    attributes: ["cn", "mail", "uid"]
)
```

### Search Scopes

| Scope | Description |
|-------|-------------|
| `.baseObject` | Only the entry named by `baseDN` |
| `.singleLevel` | Immediate children of `baseDN` |
| `.wholeSubtree` | Entire subtree below `baseDN` (default) |

### Streaming Results

For large result sets, use `searchStream()` to process entries one at a time without loading them all into memory:

```swift
let stream = try await client.searchStream(
    baseDN: "dc=example,dc=com",
    filter: .present(attribute: "mail")
)

for try await entry in stream {
    print(entry.dn)
}
```

### Working with Entries

`LDAPEntry` stores attribute values as `[String: [Data]]`. Use convenience methods to read string values:

```swift
let entry = entries.first!

// All values for an attribute
let emails = entry.stringValues(for: "mail")

// First value only
let cn = entry.firstValue(for: "cn")
```

## Filters

Filters can be built with static helpers or parsed from RFC 4515 strings.

### Filter Helpers

```swift
// Equality
.equal("cn", "John Doe")

// Presence (attribute exists)
.exists("mail")

// Substring (supports leading/trailing/middle wildcards)
.substring("cn", "Jo*")
.substring("cn", "*Doe")
.substring("cn", "J*Do*")

// Comparison
.gte("uidNumber", "1000")
.lte("uidNumber", "2000")

// Approximate
.approx("cn", "Jon Doe")

// Boolean combinations
.and([.equal("objectClass", "person"), .exists("mail")])
.or([.equal("cn", "Alice"), .equal("cn", "Bob")])
.not(.equal("status", "disabled"))
```

### Parsing Filter Strings

```swift
let filter = try LDAPFilter("(&(objectClass=person)(|(cn=John*)(mail=*@example.com)))")
```

## Modifying Data

### Add an Entry

```swift
try await client.add(
    dn: "cn=Jane Doe,ou=people,dc=example,dc=com",
    attributes: [
        LDAPAttribute(type: "objectClass", stringValues: ["inetOrgPerson"]),
        LDAPAttribute(type: "cn", stringValues: ["Jane Doe"]),
        LDAPAttribute(type: "sn", stringValues: ["Doe"]),
        LDAPAttribute(type: "mail", stringValues: ["jane@example.com"]),
    ]
)
```

### Modify an Entry

Use the convenience methods for common operations:

```swift
// Replace an attribute's values
try await client.replaceAttribute(
    dn: "cn=Jane Doe,ou=people,dc=example,dc=com",
    attribute: "mail",
    values: ["jane.doe@example.com"]
)

// Add values to an attribute
try await client.addAttribute(
    dn: "cn=Jane Doe,ou=people,dc=example,dc=com",
    attribute: "telephoneNumber",
    values: ["+1-555-0100"]
)

// Delete specific values
try await client.deleteAttribute(
    dn: "cn=Jane Doe,ou=people,dc=example,dc=com",
    attribute: "telephoneNumber",
    values: ["+1-555-0100"]
)

// Delete an entire attribute (omit values)
try await client.deleteAttribute(
    dn: "cn=Jane Doe,ou=people,dc=example,dc=com",
    attribute: "telephoneNumber"
)
```

For multiple modifications in a single request, use `modify()` directly:

```swift
try await client.modify(
    dn: "cn=Jane Doe,ou=people,dc=example,dc=com",
    modifications: [
        ModifyItem(
            operation: .replace,
            attribute: LDAPAttribute(type: "mail", stringValues: ["new@example.com"])
        ),
        ModifyItem(
            operation: .add,
            attribute: LDAPAttribute(type: "description", stringValues: ["Updated entry"])
        ),
    ]
)
```

### Delete an Entry

```swift
try await client.delete(dn: "cn=Jane Doe,ou=people,dc=example,dc=com")
```

### Rename / Move an Entry

```swift
// Rename (change RDN)
try await client.modifyDN(
    dn: "cn=Jane Doe,ou=people,dc=example,dc=com",
    newRDN: "cn=Jane Smith"
)

// Move to a different branch
try await client.modifyDN(
    dn: "cn=Jane Smith,ou=people,dc=example,dc=com",
    newRDN: "cn=Jane Smith",
    newSuperior: "ou=managers,dc=example,dc=com"
)
```

## Compare

Test whether an entry has a specific attribute value without fetching the entry:

```swift
let match = try await client.compare(
    dn: "cn=Jane Smith,ou=managers,dc=example,dc=com",
    attribute: "title",
    value: "Director"
)
// match == true if the attribute contains that value
```

## Extended Operations

### Who Am I? (RFC 4532)

```swift
let identity = try await client.whoAmI()
print(identity) // e.g. "dn:cn=admin,dc=example,dc=com"
```

### StartTLS

Usually handled automatically when using `.startTLS` security mode. Can also be triggered manually on a plain connection:

```swift
let client = LDAPClient(host: "ldap.example.com", security: .none)
try await client.connect()
try await client.startTLS()
try await client.simpleBind(dn: "cn=admin,dc=example,dc=com", password: "secret")
```

### Generic Extended Operation

```swift
let (result, oid, value) = try await client.extendedOperation(
    oid: "1.3.6.1.4.1.4203.1.11.3"  // Who Am I? OID
)
```

## Controls

Attach LDAP controls to any operation that accepts them:

```swift
let entries = try await client.search(
    baseDN: "dc=example,dc=com",
    filter: .exists("cn"),
    controls: [
        LDAPControl(oid: "1.2.840.113556.1.4.319", criticality: true, value: controlValue)
    ]
)
```

## Error Handling

All operations throw `LDAPError`:

```swift
do {
    try await client.simpleBind(dn: "cn=admin,dc=example,dc=com", password: "wrong")
} catch LDAPError.serverError(let code, let message, let matchedDN) {
    // code == .invalidCredentials
    print("Bind failed: \(message)")
} catch LDAPError.notConnected {
    print("Not connected to server")
} catch LDAPError.connectionClosed {
    print("Connection was closed")
} catch LDAPError.timeout {
    print("Operation timed out")
}
```

### Error Cases

| Case | Description |
|------|-------------|
| `.serverError(resultCode:diagnosticMessage:matchedDN:)` | Server returned a non-success result code |
| `.notConnected` | Operation attempted without an active connection |
| `.connectionClosed` | Server closed the connection |
| `.protocolError(_)` | Malformed or unexpected protocol data |
| `.timeout` | Operation exceeded the configured timeout |
| `.invalidFilter(_)` | Filter string could not be parsed |
| `.tlsError(_)` | TLS negotiation failed |
| `.ioError(_)` | Underlying transport I/O error |

## License

See [LICENSE](LICENSE) for details.
