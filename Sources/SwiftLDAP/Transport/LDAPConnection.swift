import Foundation
#if canImport(Darwin)
import Darwin
#endif

/// Configuration for connecting to an LDAP server.
public struct LDAPConnectionConfig: Sendable {
    /// The hostname or IP address of the LDAP server.
    public let host: String
    /// The port number (default: 389 for LDAP/StartTLS, 636 for LDAPS).
    public let port: UInt16
    /// The security mode for the connection.
    public let security: LDAPSecurityMode
    /// Whether to verify the server's TLS certificate chain.
    ///
    /// Set to `false` only for testing with self-signed certificates.
    /// Defaults to `true`.
    public let tlsVerifyPeer: Bool
    /// Connection timeout in seconds.
    public let connectTimeout: TimeInterval
    /// Read/write timeout in seconds.
    public let operationTimeout: TimeInterval

    public init(
        host: String,
        port: UInt16? = nil,
        security: LDAPSecurityMode = .none,
        tlsVerifyPeer: Bool = true,
        connectTimeout: TimeInterval = 30,
        operationTimeout: TimeInterval = 60
    ) {
        self.host = host
        self.port = port ?? (security == .ldaps ? 636 : 389)
        self.security = security
        self.tlsVerifyPeer = tlsVerifyPeer
        self.connectTimeout = connectTimeout
        self.operationTimeout = operationTimeout
    }
}

// MARK: - Transport Error

/// A transport-level I/O error that is `Sendable`.
struct TransportIOError: Error, Sendable {
    let message: String
    init(_ message: String) { self.message = message }
}

// MARK: - Stream Transport

/// Low-level TCP transport using POSIX sockets and Foundation streams.
///
/// Supports in-place TLS upgrade for StartTLS by applying SSL settings
/// to an already-open stream pair via `kCFStreamPropertySSLSettings`.
///
/// All blocking I/O is dispatched to dedicated serial queues to avoid
/// blocking Swift concurrency executors.
///
/// `@unchecked Sendable` is required because `InputStream` and `OutputStream`
/// do not conform to `Sendable`. Thread safety is ensured by protecting all
/// mutable state with `streamLock`, while the serial `readQueue` and
/// `writeQueue` guarantee that blocking I/O operations do not overlap.
private final class StreamTransport: @unchecked Sendable {
    private let streamLock = NSLock()
    private var _inputStream: InputStream?
    private var _outputStream: OutputStream?
    private let readQueue = DispatchQueue(label: "SwiftLDAP.StreamTransport.read")
    private let writeQueue = DispatchQueue(label: "SwiftLDAP.StreamTransport.write")
    private let verifyPeer: Bool

    private var inputStream: InputStream? {
        get {
            streamLock.lock()
            defer { streamLock.unlock() }
            return _inputStream
        }
        set {
            streamLock.lock()
            defer { streamLock.unlock() }
            _inputStream = newValue
        }
    }

    private var outputStream: OutputStream? {
        get {
            streamLock.lock()
            defer { streamLock.unlock() }
            return _outputStream
        }
        set {
            streamLock.lock()
            defer { streamLock.unlock() }
            _outputStream = newValue
        }
    }

    init(verifyPeer: Bool = true) {
        self.verifyPeer = verifyPeer
    }

    // MARK: - Connection

    /// Opens a TCP connection and optionally enables TLS immediately (for LDAPS).
    func connect(host: String, port: Int, enableTLS: Bool) async throws {
        #if canImport(Darwin)
        // Perform blocking DNS resolution + TCP connect on a background thread.
        let (input, output) = try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<(InputStream, OutputStream), any Error>) in
            DispatchQueue.global(qos: .userInitiated).async {
                do {
                    let fd = try Self.createConnectedSocket(host: host, port: port)
                    let streams = try Self.createStreams(from: fd)
                    continuation.resume(returning: streams)
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }

        if enableTLS {
            Self.applyTLSSettings(input: input, output: output, peerName: host, verifyPeer: verifyPeer)
        }

        input.open()
        output.open()
        self.inputStream = input
        self.outputStream = output
        #else
        throw LDAPError.notConnected
        #endif
    }

    /// Upgrades the existing connection to TLS (for StartTLS).
    ///
    /// Setting `kCFStreamPropertySSLSettings` on an already-open stream pair
    /// triggers a TLS handshake on the underlying socket without closing the
    /// connection. This is the standard mechanism for StartTLS.
    func startTLS(peerName: String) async throws {
        #if canImport(Darwin)
        guard let input = inputStream, let output = outputStream else {
            throw LDAPError.notConnected
        }
        Self.applyTLSSettings(input: input, output: output, peerName: peerName, verifyPeer: verifyPeer)
        #else
        throw LDAPError.tlsError("TLS not available on this platform")
        #endif
    }

    // MARK: - I/O

    /// Writes all bytes to the output stream.
    func write(_ data: [UInt8]) async throws {
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Void, any Error>) in
            writeQueue.async { [self] in
                guard let output = outputStream else {
                    continuation.resume(throwing: LDAPError.notConnected)
                    return
                }
                do {
                    try Self.writeAll(data, to: output)
                    continuation.resume()
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    /// Reads available bytes from the input stream (blocks until data arrives).
    func read() async throws -> [UInt8] {
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<[UInt8], any Error>) in
            readQueue.async { [self] in
                guard let input = inputStream else {
                    continuation.resume(throwing: LDAPError.notConnected)
                    return
                }
                var buffer = [UInt8](repeating: 0, count: 65536)
                let bytesRead = input.read(&buffer, maxLength: buffer.count)
                if bytesRead > 0 {
                    continuation.resume(returning: Array(buffer.prefix(bytesRead)))
                } else if bytesRead == 0 {
                    continuation.resume(throwing: LDAPError.connectionClosed)
                } else {
                    let desc = input.streamError?.localizedDescription ?? "Read error"
                    continuation.resume(throwing: LDAPError.ioError(TransportIOError(desc)))
                }
            }
        }
    }

    /// Closes the streams and releases resources.
    func close() {
        streamLock.lock()
        let input = _inputStream
        let output = _outputStream
        _inputStream = nil
        _outputStream = nil
        streamLock.unlock()
        input?.close()
        output?.close()
    }

    // MARK: - Private Helpers

    #if canImport(Darwin)
    /// Creates a connected TCP socket using POSIX APIs.
    ///
    /// Uses `getaddrinfo` for DNS resolution (supporting both IPv4 and IPv6),
    /// then tries each address until one connects successfully.
    private static func createConnectedSocket(host: String, port: Int) throws -> Int32 {
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SOCK_STREAM
        hints.ai_protocol = IPPROTO_TCP

        var result: UnsafeMutablePointer<addrinfo>?
        let status = getaddrinfo(host, String(port), &hints, &result)
        guard status == 0 else {
            let msg = String(cString: gai_strerror(status))
            throw LDAPError.ioError(TransportIOError("DNS resolution failed: \(msg)"))
        }
        defer { freeaddrinfo(result) }

        var lastError: String = "No addresses found"
        var info = result
        while let ai = info {
            let fd = socket(ai.pointee.ai_family, ai.pointee.ai_socktype, ai.pointee.ai_protocol)
            if fd < 0 {
                lastError = String(cString: strerror(errno))
                info = ai.pointee.ai_next
                continue
            }

            // Prevent SIGPIPE on write to a closed connection.
            var nosigpipe: Int32 = 1
            setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &nosigpipe, socklen_t(MemoryLayout<Int32>.size))

            if Darwin.connect(fd, ai.pointee.ai_addr, ai.pointee.ai_addrlen) == 0 {
                return fd
            }

            lastError = String(cString: strerror(errno))
            Darwin.close(fd)
            info = ai.pointee.ai_next
        }

        throw LDAPError.ioError(TransportIOError("Connection failed: \(lastError)"))
    }

    /// Creates Foundation stream pair from a connected socket file descriptor.
    private static func createStreams(from fd: Int32) throws -> (InputStream, OutputStream) {
        var readCF: Unmanaged<CFReadStream>?
        var writeCF: Unmanaged<CFWriteStream>?
        CFStreamCreatePairWithSocket(kCFAllocatorDefault, fd, &readCF, &writeCF)

        guard let readStream = readCF?.takeRetainedValue(),
              let writeStream = writeCF?.takeRetainedValue()
        else {
            Darwin.close(fd)
            throw LDAPError.notConnected
        }

        // Transfer socket ownership to the streams — they will close the fd.
        CFReadStreamSetProperty(
            readStream,
            CFStreamPropertyKey(rawValue: kCFStreamPropertyShouldCloseNativeSocket),
            kCFBooleanTrue
        )
        CFWriteStreamSetProperty(
            writeStream,
            CFStreamPropertyKey(rawValue: kCFStreamPropertyShouldCloseNativeSocket),
            kCFBooleanTrue
        )

        return (readStream as InputStream, writeStream as OutputStream)
    }

    /// Applies TLS/SSL settings to a stream pair.
    ///
    /// When called on an already-open stream, this triggers an in-place TLS
    /// handshake on the underlying socket (used by StartTLS). When called
    /// before `open()`, TLS is negotiated as part of opening (used by LDAPS).
    private static func applyTLSSettings(
        input: InputStream, output: OutputStream, peerName: String, verifyPeer: Bool
    ) {
        var settings: [String: Any] = [
            kCFStreamSSLPeerName as String: peerName,
        ]
        if !verifyPeer {
            // Disable certificate chain validation (for self-signed certs in test environments).
            // The raw string is used because the constant is deprecated; the value is identical.
            settings["kCFStreamSSLValidatesCertificateChain"] = false
        }
        let key = Stream.PropertyKey(rawValue: kCFStreamPropertySSLSettings as String)
        input.setProperty(settings, forKey: key)
        output.setProperty(settings, forKey: key)
    }
    #endif

    /// Writes all bytes to the output stream, handling partial writes.
    private static func writeAll(_ data: [UInt8], to output: OutputStream) throws {
        var totalWritten = 0
        while totalWritten < data.count {
            let written = data.withUnsafeBufferPointer { buffer in
                output.write(buffer.baseAddress! + totalWritten, maxLength: data.count - totalWritten)
            }
            if written < 0 {
                let desc = output.streamError?.localizedDescription ?? "Write error"
                throw LDAPError.ioError(TransportIOError(desc))
            }
            if written == 0 {
                throw LDAPError.connectionClosed
            }
            totalWritten += written
        }
    }
}

// MARK: - LDAP Connection

/// Manages a TCP connection to an LDAP server.
///
/// This actor provides a message-oriented interface over the raw TCP stream,
/// handling BER message framing (reading tag-length-value boundaries).
///
/// Uses POSIX sockets with Foundation/CoreFoundation streams for transport,
/// which supports both LDAPS (TLS from the start) and StartTLS (in-place
/// TLS upgrade on an existing connection).
actor LDAPConnection {
    private let transport: StreamTransport
    private let config: LDAPConnectionConfig
    private var isConnected = false
    private var readBuffer: [UInt8] = []

    init(config: LDAPConnectionConfig) {
        self.config = config
        self.transport = StreamTransport(verifyPeer: config.tlsVerifyPeer)
    }

    // MARK: - Connection Lifecycle

    /// Establishes the TCP connection to the LDAP server.
    ///
    /// For LDAPS mode, TLS is negotiated immediately as part of the connection.
    /// For StartTLS mode, the connection is initially plain-text; call
    /// `upgradeTLS()` after the StartTLS extended operation succeeds.
    func connect() async throws {
        try await transport.connect(
            host: config.host,
            port: Int(config.port),
            enableTLS: config.security == .ldaps
        )
        isConnected = true
    }

    /// Closes the connection.
    func disconnect() {
        transport.close()
        isConnected = false
        readBuffer = []
    }

    /// Upgrades the existing connection to TLS in-place (for StartTLS).
    ///
    /// This must only be called after the StartTLS extended operation has
    /// received a successful response from the server. The TLS handshake
    /// occurs on the same TCP connection without reconnecting.
    func upgradeTLS() async throws {
        try await transport.startTLS(peerName: config.host)
    }

    // MARK: - Message I/O

    /// Sends raw bytes over the connection.
    func send(_ data: [UInt8]) async throws {
        guard isConnected else {
            throw LDAPError.notConnected
        }
        try await transport.write(data)
    }

    /// Reads a single complete BER-encoded LDAP message from the connection.
    ///
    /// This method handles the framing: it progressively buffers enough data
    /// to parse the tag and length field, then reads the full content.
    func receiveMessage() async throws -> [UInt8] {
        // Step 1: Buffer at least tag byte + first length byte.
        try await ensureBuffered(minBytes: 2)

        // Step 2: If the length uses long form, buffer the remaining length bytes.
        let firstLengthByte = readBuffer[1]
        if firstLengthByte & 0x80 != 0 {
            let numLengthBytes = Int(firstLengthByte & 0x7F)
            guard numLengthBytes > 0 else {
                throw LDAPError.protocolError("Indefinite length not supported")
            }
            // 1 (tag) + 1 (first length byte) + numLengthBytes
            try await ensureBuffered(minBytes: 2 + numLengthBytes)
        }

        // Step 3: All length bytes are now buffered; compute total message length.
        let totalLength = peekMessageLength()

        // Step 4: Buffer the full message content.
        try await ensureBuffered(minBytes: totalLength)

        // Step 5: Extract the message.
        let message = Array(readBuffer.prefix(totalLength))
        readBuffer.removeFirst(totalLength)
        return message
    }

    // MARK: - BER Framing

    /// Computes the total length of the next BER message in the buffer
    /// (tag + length field + content bytes).
    ///
    /// Callers must ensure enough bytes are buffered for the tag and the
    /// complete length field before calling this method.
    private func peekMessageLength() -> Int {
        var offset = 1 // Skip tag byte

        let firstLengthByte = readBuffer[offset]
        offset += 1

        let contentLength: Int
        if firstLengthByte & 0x80 == 0 {
            // Short form: length is in the low 7 bits.
            contentLength = Int(firstLengthByte)
        } else {
            // Long form: first byte tells how many subsequent bytes encode the length.
            let numLengthBytes = Int(firstLengthByte & 0x7F)
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
            let chunk = try await transport.read()
            guard !chunk.isEmpty else {
                throw LDAPError.connectionClosed
            }
            readBuffer.append(contentsOf: chunk)
        }
    }
}
