import Foundation

/// An LDAP directory entry returned by a search operation.
///
/// Each entry has a distinguished name (DN) and a collection of attributes.
public struct LDAPEntry: Sendable, Equatable {
    /// The distinguished name of the entry.
    public let dn: String

    /// The attributes of the entry, keyed by attribute description (type name).
    ///
    /// Each attribute may have multiple values. Values are stored as raw `Data`
    /// since LDAP attribute values may be binary (e.g., `jpegPhoto`).
    public let attributes: [String: [Data]]
    
    public var isGroup: Bool {
        let objectClass = Set(stringValues(for: "objectClass"))
        let groupObjectClasses: Set<String> = ["groupOfNames", "posixGroup", "groupOfUniqueNames", "group", "groupOfMembers"]
        return objectClass.intersection(groupObjectClasses).isEmpty == false
    }
    
    public var isUser: Bool {
        let objectClass = Set(stringValues(for: "objectClass"))
        let userObjectClasses: Set<String> = ["inetOrgPerson", "person", "organizationalPerson", "user", "posixAccount", "account"]
        return objectClass.intersection(userObjectClasses).isEmpty == false
    }

    public init(dn: String, attributes: [String: [Data]]) {
        self.dn = dn
        self.attributes = attributes
    }

    /// Returns the string values for the named attribute, or an empty array if absent.
    public func stringValues(for attribute: String) -> [String] {
        guard let values = attributes[attribute] else { return [] }
        return values.compactMap { String(data: $0, encoding: .utf8) }
    }

    /// Returns the first string value for the named attribute, or nil if absent.
    public func firstValue(for attribute: String) -> String? {
        stringValues(for: attribute).first
    }
}

/// An LDAP attribute with its type description and set of values.
public struct LDAPAttribute: Sendable, Equatable {
    /// The attribute description (e.g., "cn", "mail", "objectClass").
    public let type: String

    /// The attribute values as raw bytes.
    public let values: [Data]

    public init(type: String, values: [Data]) {
        self.type = type
        self.values = values
    }

    /// Convenience initializer from string values.
    public init(type: String, stringValues: [String]) {
        self.type = type
        self.values = stringValues.map { Data($0.utf8) }
    }
}
