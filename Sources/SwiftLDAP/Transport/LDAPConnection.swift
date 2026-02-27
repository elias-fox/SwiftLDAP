import Foundation
#if canImport(Network)
import Network
#endif

/// Configuration for connecting to an LDAP server.
public struct LDAPConnectionConfig: Sendable {
    /// The hostname or IP address of the LDAP server.
    public let host: String
    /// The port number (default: 389 for LDAP, 636 for LDAPS).
    public let port: UInt16
    /// Whether to use TLS from the start (LDAPS).
    public let useTLS: Bool
    /// Connection timeout in seconds.
    public let connectTimeout: TimeInterval
    /// Read/write timeout in seconds.
    public let operationTimeout: TimeInterval

    public init(
        host: String,
        port: UInt16? = nil,
        useTLS: Bool = false,
        connectTimeout: TimeInterval = 30,
        operationTimeout: TimeInterval = 60
    ) {
        self.host = host
        self.port = port ?? (useTLS ? 636 : 389)
        self.useTLS = useTLS
        self.connectTimeout = connectTimeout
        self.operationTimeout = operationTimeout
    }
}

/// Manages a TCP connection to an LDAP server using Network.framework.
///
/// This actor provides a message-oriented interface over the raw TCP stream,
/// handling BER message framing (reading tag-length-value boundaries).
///
/// Uses Network.framework for native iOS/macOS support with built-in TLS.
actor LDAPConnection {
    #if canImport(Network)
    private var connection: NWConnection?
    #endif
    private let config: LDAPConnectionConfig
    private var isConnected = false
    private var readBuffer: [UInt8] = []

    init(config: LDAPConnectionConfig) {
        self.config = config
    }

    // MARK: - Connection Lifecycle

    /// Establishes the TCP connection to the LDAP server.
    func connect() async throws {
        #if canImport(Network)
        let parameters: NWParameters
        if config.useTLS {
            parameters = .tls
        } else {
            parameters = .tcp
        }

        // Configure TCP options
        if let tcpOptions = parameters.defaultProtocolStack.internetProtocol as? NWProtocolIP.Options {
            tcpOptions.version = .any
        }

        let endpoint = NWEndpoint.hostPort(
            host: NWEndpoint.Host(config.host),
            port: NWEndpoint.Port(rawValue: config.port)!
        )

        let conn = NWConnection(to: endpoint, using: parameters)
        self.connection = conn

        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            conn.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    conn.stateUpdateHandler = nil
                    continuation.resume()
                case .failed(let error):
                    conn.stateUpdateHandler = nil
                    continuation.resume(throwing: LDAPError.ioError(error))
                case .cancelled:
                    conn.stateUpdateHandler = nil
                    continuation.resume(throwing: LDAPError.connectionClosed)
                default:
                    break
                }
            }
            conn.start(queue: .global(qos: .userInitiated))
        }

        self.isConnected = true
        #else
        throw LDAPError.notConnected
        #endif
    }

    /// Closes the connection.
    func disconnect() {
        #if canImport(Network)
        connection?.cancel()
        connection = nil
        #endif
        isConnected = false
        readBuffer = []
    }

    /// Upgrades the connection to TLS (for StartTLS).
    func upgradeTLS() async throws {
        #if canImport(Network)
        guard let conn = connection else {
            throw LDAPError.notConnected
        }

        let tlsOptions = NWProtocolTLS.Options()
        let securityProtocol = tlsOptions.securityProtocolOptions
        sec_protocol_options_set_min_tls_protocol_version(securityProtocol, .TLSv12)

        // Perform the TLS handshake over the existing connection
        let metadata = conn.metadata(definition: NWProtocolTLS.definition)
        if metadata == nil {
            // Connection doesn't have TLS yet; we need to restart with TLS.
            // Network.framework doesn't support upgrading in-place, so we
            // reconnect with TLS parameters.
            conn.cancel()
            let tlsParams = NWParameters.tls
            let endpoint = NWEndpoint.hostPort(
                host: NWEndpoint.Host(config.host),
                port: NWEndpoint.Port(rawValue: config.port)!
            )
            let newConn = NWConnection(to: endpoint, using: tlsParams)
            self.connection = newConn

            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                newConn.stateUpdateHandler = { state in
                    switch state {
                    case .ready:
                        newConn.stateUpdateHandler = nil
                        continuation.resume()
                    case .failed(let error):
                        newConn.stateUpdateHandler = nil
                        continuation.resume(throwing: LDAPError.tlsError(error.localizedDescription))
                    case .cancelled:
                        newConn.stateUpdateHandler = nil
                        continuation.resume(throwing: LDAPError.connectionClosed)
                    default:
                        break
                    }
                }
                newConn.start(queue: .global(qos: .userInitiated))
            }
        }
        #else
        throw LDAPError.tlsError("TLS not available on this platform")
        #endif
    }

    // MARK: - Message I/O

    /// Sends raw bytes over the connection.
    func send(_ data: [UInt8]) async throws {
        #if canImport(Network)
        guard let conn = connection, isConnected else {
            throw LDAPError.notConnected
        }

        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            conn.send(
                content: Data(data),
                completion: .contentProcessed { error in
                    if let error {
                        continuation.resume(throwing: LDAPError.ioError(error))
                    } else {
                        continuation.resume()
                    }
                }
            )
        }
        #else
        throw LDAPError.notConnected
        #endif
    }

    /// Reads a single complete BER-encoded LDAP message from the connection.
    ///
    /// This method handles the framing: it reads enough bytes to determine the
    /// tag and length, then reads the full content before returning.
    func receiveMessage() async throws -> [UInt8] {
        // We need to read a complete TLV (Tag-Length-Value).
        // Step 1: Read the tag byte.
        try await ensureBuffered(minBytes: 2) // At least tag + 1 byte of length

        // Step 2: Determine total message length.
        let totalLength = try peekMessageLength()

        // Step 3: Ensure we have the full message.
        try await ensureBuffered(minBytes: totalLength)

        // Step 4: Extract the message.
        let message = Array(readBuffer.prefix(totalLength))
        readBuffer.removeFirst(totalLength)
        return message
    }

    // MARK: - BER Framing

    /// Peeks at the buffered data to determine the total length of the next
    /// BER message (tag + length field + content).
    private func peekMessageLength() throws -> Int {
        guard readBuffer.count >= 2 else {
            throw LDAPError.protocolError("Insufficient data for message header")
        }

        var offset = 1 // Skip tag byte

        // Read the length
        let firstLengthByte = readBuffer[offset]
        offset += 1

        let contentLength: Int
        if firstLengthByte & 0x80 == 0 {
            // Short form
            contentLength = Int(firstLengthByte)
        } else {
            let numLengthBytes = Int(firstLengthByte & 0x7F)
            guard numLengthBytes > 0 else {
                throw LDAPError.protocolError("Indefinite length not supported")
            }
            // We might need to read more for the length bytes
            let needed = offset + numLengthBytes
            guard readBuffer.count >= needed else {
                // Return a value indicating we need more data; caller will buffer more
                return readBuffer.count + numLengthBytes
            }
            var length = 0
            for i in 0..<numLengthBytes {
                length = (length << 8) | Int(readBuffer[offset + i])
            }
            offset += numLengthBytes
            contentLength = length
        }

        return offset + contentLength
    }

    /// Ensures the read buffer contains at least `minBytes` bytes,
    /// reading from the network as needed.
    private func ensureBuffered(minBytes: Int) async throws {
        while readBuffer.count < minBytes {
            let chunk = try await receiveRaw()
            guard !chunk.isEmpty else {
                throw LDAPError.connectionClosed
            }
            readBuffer.append(contentsOf: chunk)
        }
    }

    /// Reads raw bytes from the connection.
    private func receiveRaw() async throws -> [UInt8] {
        #if canImport(Network)
        guard let conn = connection, isConnected else {
            throw LDAPError.notConnected
        }

        return try await withCheckedThrowingContinuation { continuation in
            conn.receive(
                minimumIncompleteLength: 1,
                maximumLength: 65536
            ) { content, _, isComplete, error in
                if let error {
                    continuation.resume(throwing: LDAPError.ioError(error))
                } else if let content, !content.isEmpty {
                    continuation.resume(returning: Array(content))
                } else if isComplete {
                    continuation.resume(throwing: LDAPError.connectionClosed)
                } else {
                    continuation.resume(returning: [])
                }
            }
        }
        #else
        throw LDAPError.notConnected
        #endif
    }
}
