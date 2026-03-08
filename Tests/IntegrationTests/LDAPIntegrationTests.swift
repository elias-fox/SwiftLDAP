import Foundation
import Testing

@testable import SwiftLDAP

// MARK: - Test Configuration

private let testHost = ProcessInfo.processInfo.environment["LDAP_TEST_HOST"] ?? "localhost"
private let testPort = UInt16(ProcessInfo.processInfo.environment["LDAP_TEST_PORT"] ?? "1389")!
private let testLDAPSPort = UInt16(ProcessInfo.processInfo.environment["LDAP_TEST_LDAPS_PORT"] ?? "1636")!
private let adminDN = "cn=admin,dc=example,dc=org"
private let adminPassword = "adminpassword"
private let baseDN = "dc=example,dc=org"
private let peopleDN = "ou=people,dc=example,dc=org"

private let integrationEnabled = true
    //ProcessInfo.processInfo.environment["LDAP_INTEGRATION_TESTS"] != nil

// MARK: - Helpers

/// Creates a connected (but not bound) client.
private func makeClient(security: LDAPSecurityMode = .none) async throws -> LDAPClient {
    let port = security == .ldaps ? testLDAPSPort : testPort
    let client = LDAPClient(
        host: testHost,
        port: port,
        security: security,
        tlsVerifyPeer: false  // self-signed certs in Docker
    )
    try await client.connect()
    return client
}

/// Creates a connected and admin-bound client.
private func makeBoundClient(security: LDAPSecurityMode = .none) async throws -> LDAPClient {
    let client = try await makeClient(security: security)
    try await client.simpleBind(dn: adminDN, password: adminPassword)
    return client
}

// MARK: - Connection Tests

@Suite("Connection", .serialized, .enabled(if: integrationEnabled))
struct ConnectionTests {

    @Test("Connects via plain LDAP")
    func connectPlain() async throws {
        let client = try await makeClient()
        try await client.unbind()
    }

    @Test("Connects via LDAPS")
    func connectLDAPS() async throws {
        let client = try await makeClient(security: .ldaps)
        try await client.unbind()
    }

    @Test("Connects via StartTLS")
    func connectStartTLS() async throws {
        let client = try await makeClient(security: .startTLS)
        try await client.unbind()
    }
}

// MARK: - Bind Tests

@Suite("Bind", .serialized, .enabled(if: integrationEnabled))
struct BindTests {

    @Test("Anonymous bind succeeds")
    func anonymousBind() async throws {
        let client = try await makeClient()
        try await client.simpleBind()
        try await client.unbind()
    }

    @Test("Simple bind with admin credentials succeeds")
    func adminBind() async throws {
        let client = try await makeBoundClient()
        try await client.unbind()
    }

    @Test("Simple bind with wrong password throws invalidCredentials")
    func wrongPassword() async throws {
        let client = try await makeClient()
        do {
            try await client.simpleBind(dn: adminDN, password: "wrong")
            Issue.record("Expected invalidCredentials error")
        } catch let error as LDAPError {
            guard case .serverError(let code, _, _) = error else {
                Issue.record("Expected serverError, got \(error)")
                return
            }
            #expect(code == .invalidCredentials)
        }
        await client.disconnect()
    }

    @Test("Bind via LDAPS works")
    func bindLDAPS() async throws {
        let client = try await makeBoundClient(security: .ldaps)
        try await client.unbind()
    }

    @Test("Bind via StartTLS works")
    func bindStartTLS() async throws {
        let client = try await makeBoundClient(security: .startTLS)
        try await client.unbind()
    }
}

// MARK: - Search Tests

@Suite("Search", .serialized, .enabled(if: integrationEnabled))
struct SearchTests {

    @Test("Subtree search finds seeded entries")
    func subtreeSearch() async throws {
        let client = try await makeBoundClient()
        let entries = try await client.search(
            baseDN: baseDN,
            filter: .present(attribute: "objectClass")
        )
        // base + ou=people + ou=groups + 2 users + 1 group = at least 6
        #expect(entries.count >= 6)
        try await client.unbind()
    }

    @Test("Equality filter returns exact match")
    func equalityFilter() async throws {
        let client = try await makeBoundClient()
        let entries = try await client.search(
            baseDN: peopleDN,
            filter: .equal("cn", "John Doe")
        )
        #expect(entries.count == 1)
        #expect(entries[0].firstValue(for: "mail") == "john.doe@example.org")
        try await client.unbind()
    }

    @Test("Substring filter matches prefix")
    func substringFilter() async throws {
        let client = try await makeBoundClient()
        let entries = try await client.search(
            baseDN: peopleDN,
            filter: .substring("cn", "J*")
        )
        // John Doe and Jane Smith both start with J
        #expect(entries.count == 2)
        try await client.unbind()
    }

    @Test("AND filter narrows results")
    func andFilter() async throws {
        let client = try await makeBoundClient()
        let entries = try await client.search(
            baseDN: peopleDN,
            filter: .and([
                .equal("objectClass", "inetOrgPerson"),
                .equal("sn", "Smith"),
            ])
        )
        #expect(entries.count == 1)
        #expect(entries[0].firstValue(for: "cn") == "Jane Smith")
        try await client.unbind()
    }

    @Test("OR filter widens results")
    func orFilter() async throws {
        let client = try await makeBoundClient()
        let entries = try await client.search(
            baseDN: peopleDN,
            filter: .or([
                .equal("sn", "Doe"),
                .equal("sn", "Smith"),
            ])
        )
        #expect(entries.count >= 2)
        try await client.unbind()
    }

    @Test("NOT filter excludes matches")
    func notFilter() async throws {
        let client = try await makeBoundClient()
        let entries = try await client.search(
            baseDN: peopleDN,
            filter: .and([
                .equal("objectClass", "inetOrgPerson"),
                .not(.equal("sn", "Doe")),
            ])
        )
        #expect(entries.count == 1)
        #expect(entries[0].firstValue(for: "cn") == "Jane Smith")
        try await client.unbind()
    }

    @Test("Size limit caps results")
    func sizeLimit() async throws {
        let client = try await makeBoundClient()
        let entries = try await client.search(
            baseDN: baseDN,
            sizeLimit: 2,
            filter: .present(attribute: "objectClass")
        )
        #expect(entries.count <= 2)
        try await client.unbind()
    }

    @Test("Requesting specific attributes omits others")
    func specificAttributes() async throws {
        let client = try await makeBoundClient()
        let entries = try await client.search(
            baseDN: peopleDN,
            filter: .equal("cn", "John Doe"),
            attributes: ["cn", "mail"]
        )
        #expect(entries.count == 1)
        let entry = entries[0]
        #expect(entry.firstValue(for: "cn") != nil)
        #expect(entry.firstValue(for: "mail") != nil)
        #expect(entry.firstValue(for: "sn") == nil)
        try await client.unbind()
    }

    @Test("Base scope returns only the target entry")
    func baseScope() async throws {
        let client = try await makeBoundClient()
        let entries = try await client.search(
            baseDN: "cn=John Doe,\(peopleDN)",
            scope: .baseObject,
            filter: .present(attribute: "objectClass")
        )
        #expect(entries.count == 1)
        try await client.unbind()
    }

    @Test("Single-level scope excludes deeper entries")
    func singleLevelScope() async throws {
        let client = try await makeBoundClient()
        let entries = try await client.search(
            baseDN: baseDN,
            scope: .singleLevel,
            filter: .present(attribute: "objectClass")
        )
        // Direct children of base: ou=people, ou=groups (not the users inside them)
        let dns = entries.map(\.dn)
        #expect(dns.contains("ou=people,\(baseDN)"))
        #expect(dns.contains("ou=groups,\(baseDN)"))
        for dn in dns {
            #expect(!dn.hasPrefix("cn="))
        }
        try await client.unbind()
    }

    @Test("Parsed string filter works end-to-end")
    func parsedStringFilter() async throws {
        let client = try await makeBoundClient()
        let filter = try LDAPFilter.parse("(&(objectClass=inetOrgPerson)(uid=jdoe))")
        let entries = try await client.search(baseDN: peopleDN, filter: filter)
        #expect(entries.count == 1)
        #expect(entries[0].firstValue(for: "cn") == "John Doe")
        try await client.unbind()
    }

    @Test("Streaming search yields entries one at a time")
    func streamingSearch() async throws {
        let client = try await makeBoundClient()
        let stream = try await client.searchStream(
            baseDN: peopleDN,
            filter: .equal("objectClass", "inetOrgPerson")
        )
        var count = 0
        for try await entry in stream {
            #expect(!entry.dn.isEmpty)
            count += 1
        }
        #expect(count == 2)
        try await client.unbind()
    }
}

// MARK: - Mutation Tests (Add / Modify / Delete / ModifyDN)

@Suite("Mutations", .serialized, .enabled(if: integrationEnabled))
struct MutationTests {

    @Test("Add, modify, and delete an entry")
    func addModifyDelete() async throws {
        let client = try await makeBoundClient()
        let testDN = "cn=Integration Test User,\(peopleDN)"

        // Add
        try await client.add(
            dn: testDN,
            attributes: [
                LDAPAttribute(type: "objectClass", stringValues: ["inetOrgPerson"]),
                LDAPAttribute(type: "cn", stringValues: ["Integration Test User"]),
                LDAPAttribute(type: "sn", stringValues: ["Doe"]),
                LDAPAttribute(type: "mail", stringValues: ["test@example.org"]),
            ]
        )

        // Verify it exists
        var entries = try await client.search(
            baseDN: testDN, scope: .baseObject,
            filter: .present(attribute: "objectClass")
        )
        #expect(entries.count == 1)
        #expect(entries[0].firstValue(for: "mail") == "test@example.org")

        // Replace attribute
        try await client.replaceAttribute(
            dn: testDN, attribute: "mail", values: ["updated@example.org"]
        )
        entries = try await client.search(
            baseDN: testDN, scope: .baseObject,
            filter: .present(attribute: "objectClass"), attributes: ["mail"]
        )
        #expect(entries[0].firstValue(for: "mail") == "updated@example.org")

        // Add attribute
        try await client.addAttribute(
            dn: testDN, attribute: "telephoneNumber", values: ["+1-555-0100"]
        )
        entries = try await client.search(
            baseDN: testDN, scope: .baseObject,
            filter: .present(attribute: "objectClass"), attributes: ["telephoneNumber"]
        )
        #expect(entries[0].firstValue(for: "telephoneNumber") == "+1-555-0100")

        // Delete attribute
        try await client.deleteAttribute(dn: testDN, attribute: "telephoneNumber")
        entries = try await client.search(
            baseDN: testDN, scope: .baseObject,
            filter: .present(attribute: "objectClass"), attributes: ["telephoneNumber"]
        )
        #expect(entries[0].stringValues(for: "telephoneNumber").isEmpty)

        // Delete entry
        try await client.delete(dn: testDN)

        // Verify it's gone
        do {
            _ = try await client.search(
                baseDN: testDN, scope: .baseObject,
                filter: .present(attribute: "objectClass")
            )
            Issue.record("Expected noSuchObject error")
        } catch let error as LDAPError {
            guard case .serverError(let code, _, _) = error else {
                Issue.record("Expected serverError, got \(error)")
                return
            }
            #expect(code == .noSuchObject)
        }

        try await client.unbind()
    }

    @Test("Rename an entry with modifyDN")
    func modifyDN() async throws {
        let client = try await makeBoundClient()
        let origDN = "cn=Rename Me,\(peopleDN)"
        let newDN = "cn=Renamed,\(peopleDN)"

        // Create
        try await client.add(
            dn: origDN,
            attributes: [
                LDAPAttribute(type: "objectClass", stringValues: ["inetOrgPerson"]),
                LDAPAttribute(type: "cn", stringValues: ["Rename Me"]),
                LDAPAttribute(type: "sn", stringValues: ["Doe"]),
            ]
        )

        // Rename
        try await client.modifyDN(dn: origDN, newRDN: "cn=Renamed", deleteOldRDN: true)

        // Verify new DN exists
        let entries = try await client.search(
            baseDN: newDN, scope: .baseObject,
            filter: .present(attribute: "objectClass")
        )
        #expect(entries.count == 1)

        // Verify old DN is gone
        do {
            _ = try await client.search(
                baseDN: origDN, scope: .baseObject,
                filter: .present(attribute: "objectClass")
            )
            Issue.record("Old DN should not exist")
        } catch let error as LDAPError {
            guard case .serverError(let code, _, _) = error else { return }
            #expect(code == .noSuchObject)
        }

        // Cleanup
        try await client.delete(dn: newDN)
        try await client.unbind()
    }
}

// MARK: - Concurrency Tests

@Suite("Concurrency", .serialized, .enabled(if: integrationEnabled))
struct ConcurrencyTests {

    /// Fires N simultaneous searches on one connection, each with a distinct filter
    /// and a known correct answer. If any response were mis-routed to the wrong caller
    /// (the bug this demultiplexer fixes), the entry count or CN value would be wrong.
    @Test("Concurrent searches on one connection return correct results")
    func concurrentSearches() async throws {
        let client = try await makeBoundClient()

        // Interleave two distinct queries repeatedly to maximise scheduling overlap.
        let queries: [(uid: String, expectedCN: String)] = Array(
            repeatElement([("jdoe", "John Doe"), ("jsmith", "Jane Smith")], count: 5).joined()
        )

        try await withThrowingTaskGroup(of: Void.self) { group in
            for (uid, expectedCN) in queries {
                group.addTask {
                    let entries = try await client.search(
                        baseDN: peopleDN,
                        filter: .equal("uid", uid),
                        attributes: ["cn"]
                    )
                    #expect(entries.count == 1, "uid=\(uid) should match exactly one entry")
                    #expect(
                        entries.first?.firstValue(for: "cn") == expectedCN,
                        "uid=\(uid) should return cn=\(expectedCN)"
                    )
                }
            }
            try await group.waitForAll()
        }

        try await client.unbind()
    }

    /// Mixes search, compare, and whoAmI in one task group to verify that
    /// different operation types don't cross-wire each other's responses.
    @Test("Mixed concurrent operations on one connection return correct results")
    func concurrentMixedOperations() async throws {
        let client = try await makeBoundClient()

        try await withThrowingTaskGroup(of: Void.self) { group in
            for uid in ["jdoe", "jsmith", "jdoe", "jsmith"] {
                group.addTask {
                    let entries = try await client.search(
                        baseDN: peopleDN,
                        filter: .equal("uid", uid),
                        attributes: ["cn"]
                    )
                    #expect(entries.count == 1)
                }
            }
            group.addTask {
                let matched = try await client.compare(
                    dn: "cn=John Doe,\(peopleDN)", attribute: "sn", value: "Doe"
                )
                #expect(matched == true)
            }
            group.addTask {
                let matched = try await client.compare(
                    dn: "cn=Jane Smith,\(peopleDN)", attribute: "sn", value: "Doe"
                )
                #expect(matched == false)
            }
            group.addTask {
                let identity = try await client.whoAmI()
                #expect(identity.contains("admin"))
            }
            try await group.waitForAll()
        }

        try await client.unbind()
    }

    /// Runs a streaming search concurrently with several regular searches to verify
    /// the streaming demux path doesn't interfere with one-shot operations.
    @Test("Streaming search concurrent with regular searches returns correct results")
    func concurrentStreamAndSearch() async throws {
        let client = try await makeBoundClient()

        try await withThrowingTaskGroup(of: Void.self) { group in
            // Filter on uid=* — only the two seed entries carry this attribute,
            // so the count is stable even if mutation tests are running concurrently.
            group.addTask {
                let stream = try await client.searchStream(
                    baseDN: peopleDN,
                    filter: .exists("uid"),
                    attributes: ["cn"]
                )
                var count = 0
                for try await _ in stream { count += 1 }
                #expect(count == 2)
            }
            for uid in ["jdoe", "jsmith", "jdoe", "jsmith"] {
                group.addTask {
                    let entries = try await client.search(
                        baseDN: peopleDN,
                        filter: .equal("uid", uid),
                        attributes: ["cn"]
                    )
                    #expect(entries.count == 1)
                }
            }
            try await group.waitForAll()
        }

        try await client.unbind()
    }
}

// MARK: - Compare Tests

@Suite("Compare", .serialized, .enabled(if: integrationEnabled))
struct CompareTests {

    @Test("Compare returns true for matching value")
    func compareTrue() async throws {
        let client = try await makeBoundClient()
        let result = try await client.compare(
            dn: "cn=John Doe,\(peopleDN)", attribute: "sn", value: "Doe"
        )
        #expect(result == true)
        try await client.unbind()
    }

    @Test("Compare returns false for non-matching value")
    func compareFalse() async throws {
        let client = try await makeBoundClient()
        let result = try await client.compare(
            dn: "cn=John Doe,\(peopleDN)", attribute: "sn", value: "Smith"
        )
        #expect(result == false)
        try await client.unbind()
    }
}

// MARK: - Fingerprint Tests

@Suite("Fingerprint", .serialized, .enabled(if: integrationEnabled))
struct FingerprintTests {

    @Test("rootDSE accessible anonymously and server is detected as OpenLDAP")
    func anonymousFingerprint() async throws {
        let client = try await makeClient()
        let fp = try await client.fingerprint()
        #expect(fp.rawEntry != nil)
        #expect(fp.serverType == .openLDAP)
        try await client.unbind()
    }

    @Test("namingContexts contains test base DN")
    func namingContextsContainsBaseDN() async throws {
        let client = try await makeClient()
        let fp = try await client.fingerprint()
        #expect(fp.namingContexts.contains(baseDN))
        try await client.unbind()
    }

    @Test("supportedExtensions is non-empty")
    func supportedExtensionsNonEmpty() async throws {
        let client = try await makeClient()
        let fp = try await client.fingerprint()
        #expect(!fp.supportedExtensions.isEmpty)
        try await client.unbind()
    }

    @Test("subschemaSubentry is non-nil")
    func subschemaSubentryPresent() async throws {
        let client = try await makeClient()
        let fp = try await client.fingerprint()
        #expect(fp.subschemaSubentry != nil)
        try await client.unbind()
    }
}
