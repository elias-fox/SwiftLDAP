/// Errors produced by the LDAP client.
public enum LDAPError: Error, Sendable {
    /// The server returned a non-success result code.
    case serverError(resultCode: LDAPResultCode, diagnosticMessage: String, matchedDN: String)
    /// The connection is not established or has been closed.
    case notConnected
    /// The connection was unexpectedly closed by the server.
    case connectionClosed
    /// The message received from the server could not be decoded.
    case protocolError(String)
    /// A timeout occurred waiting for a response.
    case timeout
    /// A TLS/StartTLS operation failed.
    case tlsError(String)
    /// An invalid filter string was provided.
    case invalidFilter(String)
    /// The response did not match the expected message ID.
    case unexpectedMessageID(expected: Int32, received: Int32)
    /// An I/O error occurred on the underlying transport.
    case ioError(any Error & Sendable)
}
