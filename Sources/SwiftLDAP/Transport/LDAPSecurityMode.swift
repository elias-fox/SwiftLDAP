/// The security mode for an LDAP connection.
///
/// LDAP supports two distinct approaches to TLS (RFC 4513 §3):
///
/// - **LDAPS** (port 636): TLS is negotiated immediately at the transport layer
///   before any LDAP messages are exchanged. This is analogous to HTTPS.
///
/// - **StartTLS** (port 389): The client first opens a plain-text LDAP connection,
///   then sends a StartTLS extended operation (OID 1.3.6.1.4.1.1466.20037) to
///   upgrade the *existing* TCP connection to TLS in-place (RFC 4511 §4.14.1).
///
/// These are mutually exclusive — a connection uses one or the other.
public enum LDAPSecurityMode: Sendable, Equatable {
    /// No encryption. LDAP traffic is sent in the clear over TCP.
    case none

    /// StartTLS: connect to the standard LDAP port (389) over plain TCP,
    /// then upgrade to TLS using the StartTLS extended operation before
    /// any credentials are sent.
    case startTLS

    /// LDAPS: establish TLS immediately when connecting, using the
    /// dedicated LDAPS port (636).
    case ldaps
}
