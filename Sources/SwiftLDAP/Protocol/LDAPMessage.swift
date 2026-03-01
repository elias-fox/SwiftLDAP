import Foundation

/// The scope of an LDAP search operation (RFC 4511 §4.5.1).
public enum SearchScope: Int, Sendable {
    /// Search only the base object.
    case baseObject = 0
    /// Search one level below the base.
    case singleLevel = 1
    /// Search the entire subtree rooted at the base.
    case wholeSubtree = 2
}

/// How aliases are dereferenced during search (RFC 4511 §4.5.1).
public enum DerefAliases: Int, Sendable {
    /// Never dereference aliases.
    case neverDerefAliases = 0
    /// Dereference while searching subordinates of the base.
    case derefInSearching = 1
    /// Dereference when locating the base object.
    case derefFindingBaseObj = 2
    /// Always dereference aliases.
    case derefAlways = 3
}

/// The type of modification in a Modify operation (RFC 4511 §4.6).
public enum ModifyOperation: Int, Sendable {
    /// Add values to the attribute.
    case add = 0
    /// Delete values from the attribute (or delete the attribute if values is empty).
    case delete = 1
    /// Replace all existing values of the attribute.
    case replace = 2
}

/// An LDAP control attached to a request or response (RFC 4511 §4.1.11).
public struct LDAPControl: Sendable, Equatable {
    /// The OID identifying the control.
    public let oid: String
    /// Whether the control is critical.
    public let criticality: Bool
    /// Optional control value.
    public let value: Data?

    public init(oid: String, criticality: Bool = false, value: Data? = nil) {
        self.oid = oid
        self.criticality = criticality
        self.value = value
    }
}

/// A single modification item for a Modify request.
public struct ModifyItem: Sendable {
    public let operation: ModifyOperation
    public let attribute: LDAPAttribute

    public init(operation: ModifyOperation, attribute: LDAPAttribute) {
        self.operation = operation
        self.attribute = attribute
    }
}

/// Represents the protocol operation within an LDAP message.
///
/// Each variant maps to an ASN.1 CHOICE in the LDAPMessage definition (RFC 4511 §4.2).
public enum LDAPOperation: Sendable {
    // MARK: - Requests

    /// Bind request: authenticate to the server.
    case bindRequest(version: Int, name: String, authentication: BindAuthentication)

    /// Unbind request: graceful disconnect (no response expected).
    case unbindRequest

    /// Search request.
    case searchRequest(SearchParameters)

    /// Modify request: modify attributes of an entry.
    case modifyRequest(dn: String, modifications: [ModifyItem])

    /// Add request: add a new entry.
    case addRequest(dn: String, attributes: [LDAPAttribute])

    /// Delete request: remove an entry.
    case deleteRequest(dn: String)

    /// Modify DN request: rename or move an entry.
    case modifyDNRequest(dn: String, newRDN: String, deleteOldRDN: Bool, newSuperior: String?)

    /// Compare request: test an attribute value assertion.
    case compareRequest(dn: String, attributeDescription: String, assertionValue: Data)

    /// Abandon request: abandon a pending operation.
    case abandonRequest(messageID: Int32)

    /// Extended request.
    case extendedRequest(oid: String, value: Data?)

    // MARK: - Responses

    /// Bind response.
    case bindResponse(LDAPResult, serverSASLCreds: Data?)

    /// Search result entry (one per matching entry).
    case searchResultEntry(LDAPEntry)

    /// Search result reference (continuation reference).
    case searchResultReference([String])

    /// Search result done (final response to a search).
    case searchResultDone(LDAPResult)

    /// Modify response.
    case modifyResponse(LDAPResult)

    /// Add response.
    case addResponse(LDAPResult)

    /// Delete response.
    case deleteResponse(LDAPResult)

    /// Modify DN response.
    case modifyDNResponse(LDAPResult)

    /// Compare response.
    case compareResponse(LDAPResult)

    /// Extended response.
    case extendedResponse(LDAPResult, oid: String?, value: Data?)

    /// Intermediate response.
    case intermediateResponse(oid: String?, value: Data?)
}

/// Authentication mechanism for a bind request.
public enum BindAuthentication: Sendable {
    /// Simple authentication (clear-text password or anonymous bind).
    case simple(password: String)
    /// SASL authentication.
    case sasl(mechanism: String, credentials: Data?)
}

/// Parameters for a search request (RFC 4511 §4.5.1).
public struct SearchParameters: Sendable {
    /// The base DN for the search.
    public let baseDN: String
    /// The scope of the search.
    public let scope: SearchScope
    /// How to dereference aliases.
    public let derefAliases: DerefAliases
    /// Maximum number of entries to return (0 = no limit).
    public let sizeLimit: Int
    /// Maximum time in seconds for the search (0 = no limit).
    public let timeLimit: Int
    /// If true, return only attribute types (no values).
    public let typesOnly: Bool
    /// The search filter.
    public let filter: LDAPFilter
    /// Attributes to return (empty = all user attributes).
    public let attributes: [String]

    public init(
        baseDN: String,
        scope: SearchScope = .wholeSubtree,
        derefAliases: DerefAliases = .neverDerefAliases,
        sizeLimit: Int = 0,
        timeLimit: Int = 0,
        typesOnly: Bool = false,
        filter: LDAPFilter,
        attributes: [String] = []
    ) {
        self.baseDN = baseDN
        self.scope = scope
        self.derefAliases = derefAliases
        self.sizeLimit = sizeLimit
        self.timeLimit = timeLimit
        self.typesOnly = typesOnly
        self.filter = filter
        self.attributes = attributes
    }
}

/// The result portion of an LDAP response (RFC 4511 §4.1.9).
public struct LDAPResult: Sendable, Equatable {
    /// The result code.
    public let resultCode: LDAPResultCode
    /// The matched DN (used when resultCode is noSuchObject).
    public let matchedDN: String
    /// A diagnostic message from the server.
    public let diagnosticMessage: String
    /// Referral URIs, if the result code is `referral`.
    public let referrals: [String]

    public init(
        resultCode: LDAPResultCode,
        matchedDN: String = "",
        diagnosticMessage: String = "",
        referrals: [String] = []
    ) {
        self.resultCode = resultCode
        self.matchedDN = matchedDN
        self.diagnosticMessage = diagnosticMessage
        self.referrals = referrals
    }
}
