import Foundation

/// A pure-Swift LDAP client with async/await support.
///
/// Implements the LDAPv3 protocol (RFC 4511) over TCP with optional TLS.
/// Requires macOS 13+ or iOS 16+ (Darwin only).
///
/// The client supports three security modes:
/// - **No TLS**: Plain-text connection (`.none`).
/// - **LDAPS**: TLS from the start on port 636 (`.ldaps`).
/// - **StartTLS**: Plain connection on port 389, upgraded to TLS via the
///   StartTLS extended operation (`.startTLS`). The upgrade happens
///   automatically during `connect()`.
///
/// ## Usage
/// ```swift
/// // LDAPS (TLS from the start)
/// let client = LDAPClient(host: "ldap.example.com", security: .ldaps)
/// try await client.connect()
///
/// // StartTLS (upgrade existing connection)
/// let client = LDAPClient(host: "ldap.example.com", security: .startTLS)
/// try await client.connect() // automatically negotiates StartTLS
///
/// try await client.simpleBind(dn: "cn=admin,dc=example,dc=com", password: "secret")
///
/// let entries = try await client.search(
///     baseDN: "dc=example,dc=com",
///     filter: .equal("cn", "John Doe")
/// )
/// for entry in entries {
///     print(entry.dn)
/// }
///
/// try await client.unbind()
/// ```
public actor LDAPClient {
    private let connection: LDAPConnection
    private let config: LDAPConnectionConfig
    private var nextMessageID: Int32 = 1

    /// Creates a new LDAP client.
    ///
    /// - Parameters:
    ///   - host: The LDAP server hostname.
    ///   - port: The port number (defaults to 389 for `.none`/`.startTLS`, 636 for `.ldaps`).
    ///   - security: The security mode (default: `.startTLS`).
    ///   - tlsVerifyPeer: Whether to verify the server's certificate chain (default: `true`).
    ///     Set to `false` only for testing with self-signed certificates.
    ///   - connectTimeout: Connection timeout in seconds.
    ///   - operationTimeout: Per-operation timeout in seconds.
    ///   - maxSearchEntries: Maximum number of entries `search()` will accumulate (0 = no limit).
    public init(
        host: String,
        port: UInt16? = nil,
        security: LDAPSecurityMode = .startTLS,
        tlsVerifyPeer: Bool = true,
        connectTimeout: TimeInterval = 30,
        operationTimeout: TimeInterval = 60,
        maxSearchEntries: Int = 0
    ) {
        self.config = LDAPConnectionConfig(
            host: host,
            port: port,
            security: security,
            tlsVerifyPeer: tlsVerifyPeer,
            connectTimeout: connectTimeout,
            operationTimeout: operationTimeout,
            maxSearchEntries: maxSearchEntries
        )
        self.connection = LDAPConnection(config: self.config)
    }

    /// Creates a new LDAP client from a connection configuration.
    public init(config: LDAPConnectionConfig) {
        self.config = config
        self.connection = LDAPConnection(config: config)
    }

    // MARK: - Connection

    /// Connects to the LDAP server.
    ///
    /// For `.ldaps` mode, TLS is negotiated as part of the TCP connection.
    /// For `.startTLS` mode, a plain TCP connection is established first,
    /// then the StartTLS extended operation is sent to upgrade the connection
    /// to TLS in-place before returning.
    public func connect() async throws {
        try await connection.connect()

        if config.security == .startTLS {
            do {
                try await startTLS()
            } catch {
                await connection.disconnect()
                throw error
            }
        }
    }

    /// Disconnects from the LDAP server.
    public func disconnect() async {
        await connection.disconnect()
    }

    // MARK: - Bind (RFC 4511 §4.2)

    /// Performs a simple bind (authentication) with the given DN and password.
    ///
    /// To perform an anonymous bind, pass empty strings for both parameters.
    ///
    /// - Parameters:
    ///   - dn: The distinguished name to bind as.
    ///   - password: The password.
    /// - Returns: The bind result from the server.
    @discardableResult
    public func simpleBind(dn: String = "", password: String = "") async throws -> LDAPResult {
        try await performOperation(.bindRequest(version: 3, name: dn, authentication: .simple(password: password))) { op in
            guard case .bindResponse(let result, _) = op else {
                throw LDAPError.protocolError("Expected BindResponse")
            }
            try throwIfError(result)
            return result
        }
    }

    /// Performs a SASL bind.
    ///
    /// - Parameters:
    ///   - dn: The distinguished name (often empty for SASL).
    ///   - mechanism: The SASL mechanism name (e.g., "EXTERNAL", "PLAIN").
    ///   - credentials: Optional SASL credentials.
    /// - Returns: The bind result and optional server SASL credentials.
    @discardableResult
    public func saslBind(
        dn: String = "",
        mechanism: String,
        credentials: Data? = nil
    ) async throws -> (result: LDAPResult, serverCredentials: Data?) {
        let messageID = allocateMessageID()
        let requestBytes = LDAPCodec.encode(
            messageID: messageID,
            operation: .bindRequest(
                version: 3,
                name: dn,
                authentication: .sasl(mechanism: mechanism, credentials: credentials)
            )
        )
        let conn = connection
        let responseData = try await withTimeout(config.operationTimeout) {
            try await conn.sendAndReceive(messageID: messageID, data: requestBytes)
        }
        let (_, operation, _) = try LDAPCodec.decode(responseData)
        guard case .bindResponse(let result, let serverCreds) = operation else {
            throw LDAPError.protocolError("Expected BindResponse")
        }
        if result.resultCode != .success && result.resultCode != .saslBindInProgress {
            throw LDAPError.serverError(
                resultCode: result.resultCode,
                diagnosticMessage: result.diagnosticMessage,
                matchedDN: result.matchedDN
            )
        }
        return (result, serverCreds)
    }

    // MARK: - Unbind (RFC 4511 §4.3)

    /// Sends an unbind request and closes the connection.
    ///
    /// After calling unbind, the client must not be used for further operations.
    /// Per RFC 4511, the unbind operation is not a request-response: the server
    /// simply closes the connection upon receiving it.
    public func unbind() async throws {
        let messageID = allocateMessageID()
        let requestBytes = LDAPCodec.encode(
            messageID: messageID,
            operation: .unbindRequest
        )
        try await connection.sendFireAndForget(requestBytes)
        await connection.disconnect()
    }

    // MARK: - Search (RFC 4511 §4.5)

    /// Performs an LDAP search and returns all matching entries.
    ///
    /// - Parameters:
    ///   - baseDN: The base distinguished name for the search.
    ///   - scope: The search scope (default: whole subtree).
    ///   - derefAliases: How to handle aliases (default: never).
    ///   - sizeLimit: Maximum entries to return (0 = unlimited).
    ///   - timeLimit: Maximum time in seconds (0 = unlimited).
    ///   - typesOnly: If true, return only attribute types without values.
    ///   - filter: The search filter.
    ///   - attributes: Attributes to return (empty = all user attributes).
    ///   - controls: Optional LDAP controls.
    /// - Returns: An array of matching entries.
    public func search(
        baseDN: String,
        scope: SearchScope = .wholeSubtree,
        derefAliases: DerefAliases = .neverDerefAliases,
        sizeLimit: Int = 0,
        timeLimit: Int = 0,
        typesOnly: Bool = false,
        filter: LDAPFilter = .exists("objectClass"),
        attributes: [String] = [],
        controls: [LDAPControl] = []
    ) async throws -> [LDAPEntry] {
        let messageID = allocateMessageID()

        let params = SearchParameters(
            baseDN: baseDN,
            scope: scope,
            derefAliases: derefAliases,
            sizeLimit: sizeLimit,
            timeLimit: timeLimit,
            typesOnly: typesOnly,
            filter: filter,
            attributes: attributes
        )

        let requestBytes = LDAPCodec.encode(
            messageID: messageID,
            operation: .searchRequest(params),
            controls: controls
        )

        let rawStream = try await connection.sendForStream(messageID: messageID, data: requestBytes)

        var entries: [LDAPEntry] = []
        for try await responseData in rawStream {
            let (_, operation, _) = try LDAPCodec.decode(responseData)
            switch operation {
            case .searchResultEntry(let entry):
                entries.append(entry)
                if sizeLimit > 0 && entries.count >= sizeLimit {
                    // Breaking the loop cancels the stream, triggering onTermination → removePending.
                    return entries
                }
                if config.maxSearchEntries > 0 && entries.count > config.maxSearchEntries {
                    throw LDAPError.protocolError("Search result count exceeds client limit")
                }
            case .searchResultReference:
                // Skip referrals; could be exposed via a callback in the future.
                continue
            case .searchResultDone(let result):
                await connection.finishStream(messageID: messageID, error: nil)
                try throwIfError(result)
                return entries
            default:
                throw LDAPError.protocolError("Unexpected response during search")
            }
        }
        return entries
    }

    /// Performs an LDAP search and returns results as an `AsyncStream`.
    ///
    /// This is useful for large result sets where you want to process entries
    /// one at a time rather than loading them all into memory.
    public func searchStream(
        baseDN: String,
        scope: SearchScope = .wholeSubtree,
        derefAliases: DerefAliases = .neverDerefAliases,
        sizeLimit: Int = 0,
        timeLimit: Int = 0,
        typesOnly: Bool = false,
        filter: LDAPFilter,
        attributes: [String] = [],
        controls: [LDAPControl] = []
    ) async throws -> AsyncThrowingStream<LDAPEntry, Error> {
        let messageID = allocateMessageID()

        let params = SearchParameters(
            baseDN: baseDN,
            scope: scope,
            derefAliases: derefAliases,
            sizeLimit: sizeLimit,
            timeLimit: timeLimit,
            typesOnly: typesOnly,
            filter: filter,
            attributes: attributes
        )

        let requestBytes = LDAPCodec.encode(
            messageID: messageID,
            operation: .searchRequest(params),
            controls: controls
        )

        let rawStream = try await connection.sendForStream(messageID: messageID, data: requestBytes)
        let connection = self.connection

        return AsyncThrowingStream { continuation in
            let task = Task {
                do {
                    for try await responseData in rawStream {
                        try Task.checkCancellation()
                        let (_, operation, _) = try LDAPCodec.decode(responseData)
                        switch operation {
                        case .searchResultEntry(let entry):
                            continuation.yield(entry)
                        case .searchResultReference:
                            continue
                        case .searchResultDone(let result):
                            await connection.finishStream(messageID: messageID, error: nil)
                            if result.resultCode != .success
                                && result.resultCode != .sizeLimitExceeded
                            {
                                continuation.finish(throwing: LDAPError.serverError(
                                    resultCode: result.resultCode,
                                    diagnosticMessage: result.diagnosticMessage,
                                    matchedDN: result.matchedDN
                                ))
                            } else {
                                continuation.finish()
                            }
                            return
                        default:
                            continuation.finish(
                                throwing: LDAPError.protocolError("Unexpected response during search"))
                            return
                        }
                    }
                    continuation.finish()
                } catch {
                    continuation.finish(throwing: error)
                }
            }
            // Cancel the processing task when the consumer exits the stream.
            // This propagates cancellation to rawStream, which triggers its
            // onTermination → removePending on the connection.
            continuation.onTermination = { _ in task.cancel() }
        }
    }

    // MARK: - Modify (RFC 4511 §4.6)

    /// Modifies an existing LDAP entry.
    ///
    /// - Parameters:
    ///   - dn: The DN of the entry to modify.
    ///   - modifications: The list of modifications to apply.
    ///   - controls: Optional LDAP controls.
    /// - Returns: The modify result.
    @discardableResult
    public func modify(
        dn: String,
        modifications: [ModifyItem],
        controls: [LDAPControl] = []
    ) async throws -> LDAPResult {
        try await performOperation(.modifyRequest(dn: dn, modifications: modifications), controls: controls) { op in
            guard case .modifyResponse(let result) = op else {
                throw LDAPError.protocolError("Expected ModifyResponse")
            }
            try throwIfError(result)
            return result
        }
    }

    // MARK: - Add (RFC 4511 §4.7)

    /// Adds a new LDAP entry.
    ///
    /// - Parameters:
    ///   - dn: The DN of the new entry.
    ///   - attributes: The attributes for the new entry.
    ///   - controls: Optional LDAP controls.
    /// - Returns: The add result.
    @discardableResult
    public func add(
        dn: String,
        attributes: [LDAPAttribute],
        controls: [LDAPControl] = []
    ) async throws -> LDAPResult {
        try await performOperation(.addRequest(dn: dn, attributes: attributes), controls: controls) { op in
            guard case .addResponse(let result) = op else {
                throw LDAPError.protocolError("Expected AddResponse")
            }
            try throwIfError(result)
            return result
        }
    }

    // MARK: - Delete (RFC 4511 §4.8)

    /// Deletes an LDAP entry.
    ///
    /// - Parameters:
    ///   - dn: The DN of the entry to delete.
    ///   - controls: Optional LDAP controls.
    /// - Returns: The delete result.
    @discardableResult
    public func delete(
        dn: String,
        controls: [LDAPControl] = []
    ) async throws -> LDAPResult {
        try await performOperation(.deleteRequest(dn: dn), controls: controls) { op in
            guard case .deleteResponse(let result) = op else {
                throw LDAPError.protocolError("Expected DeleteResponse")
            }
            try throwIfError(result)
            return result
        }
    }

    // MARK: - Modify DN (RFC 4511 §4.9)

    /// Renames or moves an LDAP entry.
    ///
    /// - Parameters:
    ///   - dn: The current DN of the entry.
    ///   - newRDN: The new relative distinguished name.
    ///   - deleteOldRDN: Whether to delete the old RDN values.
    ///   - newSuperior: Optional new parent DN (to move the entry).
    ///   - controls: Optional LDAP controls.
    /// - Returns: The modify DN result.
    @discardableResult
    public func modifyDN(
        dn: String,
        newRDN: String,
        deleteOldRDN: Bool = true,
        newSuperior: String? = nil,
        controls: [LDAPControl] = []
    ) async throws -> LDAPResult {
        try await performOperation(
            .modifyDNRequest(dn: dn, newRDN: newRDN, deleteOldRDN: deleteOldRDN, newSuperior: newSuperior),
            controls: controls
        ) { op in
            guard case .modifyDNResponse(let result) = op else {
                throw LDAPError.protocolError("Expected ModifyDNResponse")
            }
            try throwIfError(result)
            return result
        }
    }

    // MARK: - Compare (RFC 4511 §4.10)

    /// Compares an attribute value assertion against an entry.
    ///
    /// - Parameters:
    ///   - dn: The DN of the entry to compare against.
    ///   - attribute: The attribute description.
    ///   - value: The assertion value.
    ///   - controls: Optional LDAP controls.
    /// - Returns: `true` if the assertion matched (compareTrue), `false` if it didn't (compareFalse).
    public func compare(
        dn: String,
        attribute: String,
        value: String,
        controls: [LDAPControl] = []
    ) async throws -> Bool {
        try await performOperation(
            .compareRequest(dn: dn, attributeDescription: attribute, assertionValue: Data(value.utf8)),
            controls: controls
        ) { op in
            guard case .compareResponse(let result) = op else {
                throw LDAPError.protocolError("Expected CompareResponse")
            }
            switch result.resultCode {
            case .compareTrue: return true
            case .compareFalse: return false
            default:
                throw LDAPError.serverError(
                    resultCode: result.resultCode,
                    diagnosticMessage: result.diagnosticMessage,
                    matchedDN: result.matchedDN
                )
            }
        }
    }

    // MARK: - Abandon (RFC 4511 §4.11)

    /// Abandons a previously submitted operation.
    ///
    /// - Parameter messageID: The message ID of the operation to abandon.
    public func abandon(messageID: Int32) async throws {
        let abandonID = allocateMessageID()
        let requestBytes = LDAPCodec.encode(
            messageID: abandonID,
            operation: .abandonRequest(messageID: messageID)
        )
        try await connection.sendFireAndForget(requestBytes)
        // Abandon has no response per RFC 4511.
    }

    // MARK: - Extended Operations (RFC 4511 §4.12)

    /// Sends an extended request to the server.
    ///
    /// - Parameters:
    ///   - oid: The OID of the extended operation.
    ///   - value: Optional request value.
    ///   - controls: Optional LDAP controls.
    /// - Returns: A tuple of the result, optional response OID, and optional response value.
    public func extendedOperation(
        oid: String,
        value: Data? = nil,
        controls: [LDAPControl] = []
    ) async throws -> (result: LDAPResult, oid: String?, value: Data?) {
        try await performOperation(.extendedRequest(oid: oid, value: value), controls: controls) { op in
            guard case .extendedResponse(let result, let respOID, let respValue) = op else {
                throw LDAPError.protocolError("Expected ExtendedResponse")
            }
            try throwIfError(result)
            return (result, respOID, respValue)
        }
    }

    /// Performs the StartTLS extended operation (RFC 4511 §4.14.1, RFC 4513).
    ///
    /// This upgrades the connection to TLS. Must be called before binding
    /// if the server requires encryption.
    public func startTLS() async throws {
        _ = try await extendedOperation(
            oid: "1.3.6.1.4.1.1466.20037" // OID for StartTLS
        )

        try await connection.upgradeTLS()
    }

    /// Sends a "Who Am I?" extended request (RFC 4532).
    ///
    /// - Returns: The authorization identity string.
    public func whoAmI() async throws -> String {
        let (_, _, value) = try await extendedOperation(
            oid: "1.3.6.1.4.1.4203.1.11.3" // OID for Who Am I?
        )

        if let value {
            return String(decoding: value, as: UTF8.self)
        }
        return ""
    }

    // MARK: - Directory Information (RFC 4512 §5.1)

    /// Queries the server's rootDSE and returns a structured fingerprint of its
    /// capabilities and software identity.
    ///
    /// If the server restricts anonymous access to the rootDSE, returns a fingerprint
    /// with `serverType == .unknown` and `rawEntry == nil` rather than throwing.
    public func fingerprint() async throws -> LDAPServerFingerprint {
        let entries = try await search(
            baseDN: "",
            scope: .baseObject,
            filter: .present(attribute: "objectClass"),
            attributes: [
                "vendorName", "vendorVersion", "namingContexts",
                "supportedExtension", "supportedControl",
                "supportedFeatures", "supportedSASLMechanisms",
                "supportedCapabilities",
                "subschemaSubentry",
            ]
        )
        return LDAPServerFingerprint(rootDSEEntries: entries)
    }

    // MARK: - Convenience Methods

    /// Adds an attribute value to an existing entry.
    @discardableResult
    public func addAttribute(
        dn: String,
        attribute: String,
        values: [String]
    ) async throws -> LDAPResult {
        try await modify(
            dn: dn,
            modifications: [
                ModifyItem(
                    operation: .add,
                    attribute: LDAPAttribute(type: attribute, stringValues: values)
                )
            ]
        )
    }

    /// Replaces an attribute's values on an existing entry.
    @discardableResult
    public func replaceAttribute(
        dn: String,
        attribute: String,
        values: [String]
    ) async throws -> LDAPResult {
        try await modify(
            dn: dn,
            modifications: [
                ModifyItem(
                    operation: .replace,
                    attribute: LDAPAttribute(type: attribute, stringValues: values)
                )
            ]
        )
    }

    /// Deletes an attribute (or specific values) from an existing entry.
    @discardableResult
    public func deleteAttribute(
        dn: String,
        attribute: String,
        values: [String] = []
    ) async throws -> LDAPResult {
        try await modify(
            dn: dn,
            modifications: [
                ModifyItem(
                    operation: .delete,
                    attribute: LDAPAttribute(type: attribute, stringValues: values)
                )
            ]
        )
    }

    // MARK: - Private Helpers

    /// Encodes, sends, receives, and decodes a single-response LDAP operation.
    ///
    /// Handles the common scaffolding shared by all simple request-response operations:
    /// message ID allocation, BER encoding, send/receive, decoding, and message ID validation.
    /// The `extract` closure performs operation-specific response matching and error handling.
    private func performOperation<T>(
        _ operation: LDAPOperation,
        controls: [LDAPControl] = [],
        extract: (LDAPOperation) throws -> T
    ) async throws -> T {
        let messageID = allocateMessageID()
        let requestBytes = LDAPCodec.encode(messageID: messageID, operation: operation, controls: controls)
        let conn = connection
        let responseData = try await withTimeout(config.operationTimeout) {
            try await conn.sendAndReceive(messageID: messageID, data: requestBytes)
        }
        let (_, respOp, _) = try LDAPCodec.decode(responseData)
        return try extract(respOp)
    }

    /// Runs `operation` with a deadline, throwing `LDAPError.timeout` if it exceeds `seconds`.
    ///
    /// On timeout the operation task is cancelled, which causes the demultiplexer's
    /// `withTaskCancellationHandler` to remove the pending entry and resume any waiting
    /// continuation with `CancellationError` (surfaced here as `LDAPError.timeout`).
    private func withTimeout<T: Sendable>(
        _ seconds: TimeInterval,
        operation: @escaping @Sendable () async throws -> T
    ) async throws -> T {
        try await withThrowingTaskGroup(of: T.self) { group in
            group.addTask { try await operation() }
            group.addTask {
                try await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
                throw LDAPError.timeout
            }
            guard let result = try await group.next() else {
                throw LDAPError.timeout
            }
            group.cancelAll()
            return result
        }
    }

    private func allocateMessageID() -> Int32 {
        let id = nextMessageID
        nextMessageID += 1
        if nextMessageID >= Int32.max {
            nextMessageID = 1
        }
        return id
    }

    private func throwIfError(_ result: LDAPResult) throws {
        guard result.resultCode == .success || result.resultCode == .sizeLimitExceeded else {
            throw LDAPError.serverError(
                resultCode: result.resultCode,
                diagnosticMessage: result.diagnosticMessage,
                matchedDN: result.matchedDN
            )
        }
    }
}
