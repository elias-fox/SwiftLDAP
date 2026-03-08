import Foundation

/// The detected software type of an LDAP server.
public enum LDAPServerType: Sendable, Equatable, CustomStringConvertible {
    case openLDAP
    case activeDirectory
    case directoryServer389
    case apacheDS
    case unknown

    public var description: String {
        switch self {
        case .openLDAP: return "OpenLDAP"
        case .activeDirectory: return "Active Directory"
        case .directoryServer389: return "389 Directory Server"
        case .apacheDS: return "ApacheDS"
        case .unknown: return "Unknown"
        }
    }
}

/// Structured information about an LDAP server's capabilities and software identity,
/// derived from the server's rootDSE entry (RFC 4512 §5.1).
public struct LDAPServerFingerprint: Sendable {
    /// Detected server software type.
    public let serverType: LDAPServerType
    /// Value of the `vendorName` rootDSE attribute, if present.
    public let vendorName: String?
    /// Value of the `vendorVersion` rootDSE attribute, if present.
    public let vendorVersion: String?
    /// Values of the `namingContexts` rootDSE attribute.
    public let namingContexts: [String]
    /// OIDs advertised in `supportedExtensions`.
    public let supportedExtensions: [String]
    /// OIDs advertised in `supportedControl` / `supportedControls`.
    public let supportedControls: [String]
    /// OIDs advertised in `supportedFeatures`.
    public let supportedFeatures: [String]
    /// Mechanism names advertised in `supportedSASLMechanisms`.
    public let supportedSASLMechanisms: [String]
    /// OIDs advertised in `supportedCapabilities` (Active Directory-specific attribute).
    public let supportedCapabilities: [String]
    /// Value of the `subschemaSubentry` attribute, if present.
    public let subschemaSubentry: String?
    /// The raw rootDSE entry. `nil` when the server returned no entries (e.g. anonymous access
    /// was denied), in which case all other fields are empty/nil and `serverType` is `.unknown`.
    public let rawEntry: LDAPEntry?

    init(rootDSEEntries: [LDAPEntry]) {
        guard let entry = rootDSEEntries.first else {
            serverType = .unknown
            vendorName = nil
            vendorVersion = nil
            namingContexts = []
            supportedExtensions = []
            supportedControls = []
            supportedFeatures = []
            supportedSASLMechanisms = []
            supportedCapabilities = []
            subschemaSubentry = nil
            rawEntry = nil
            return
        }

        rawEntry = entry

        // Case-insensitive attribute lookup
        func values(for key: String) -> [String] {
            let lower = key.lowercased()
            for (k, v) in entry.attributes where k.lowercased() == lower {
                return v.compactMap { String(data: $0, encoding: .utf8) }
            }
            return []
        }

        func first(for key: String) -> String? {
            values(for: key).first
        }

        vendorName = first(for: "vendorName")
        vendorVersion = first(for: "vendorVersion")
        namingContexts = values(for: "namingContexts")
        // RFC 4512 uses "supportedExtension" (singular); merge with plural fallback
        let extensions = values(for: "supportedExtension") + values(for: "supportedExtensions")
        supportedExtensions = Array(OrderedSet(extensions))
        // RFC 4512 uses "supportedControl" (singular); merge with plural fallback
        let controls = values(for: "supportedControl") + values(for: "supportedControls")
        supportedControls = Array(OrderedSet(controls))
        supportedFeatures = values(for: "supportedFeatures")
        supportedSASLMechanisms = values(for: "supportedSASLMechanisms")
        supportedCapabilities = values(for: "supportedCapabilities")
        subschemaSubentry = first(for: "subschemaSubentry")

        serverType = Self.detect(
            vendorName: vendorName,
            supportedExtensions: supportedExtensions,
            supportedControls: supportedControls,
            supportedFeatures: supportedFeatures,
            supportedCapabilities: supportedCapabilities
        )
    }

    private static func detect(
        vendorName: String?,
        supportedExtensions: [String],
        supportedControls: [String],
        supportedFeatures: [String],
        supportedCapabilities: [String]
    ) -> LDAPServerType {
        let vendor = vendorName?.lowercased() ?? ""

        // 1. Active Directory — authoritative MS capability OIDs, checked first
        let adCapV4 = "1.2.840.113556.1.4.800"   // AD V4
        let adCapV51 = "1.2.840.113556.1.4.1670"  // AD V5.1
        if supportedCapabilities.contains(adCapV4) || supportedCapabilities.contains(adCapV51) {
            return .activeDirectory
        }

        // 2. OpenLDAP — vendorName or OID prefix 1.3.6.1.4.1.4203.
        let openLDAPPrefix = "1.3.6.1.4.1.4203."
        if vendor.contains("openldap")
            || supportedExtensions.contains(where: { $0.hasPrefix(openLDAPPrefix) })
            || supportedFeatures.contains(where: { $0.hasPrefix(openLDAPPrefix) })
        {
            return .openLDAP
        }

        // 3. 389-DS
        if vendor.contains("389-ds") || vendor.contains("red hat") || vendor.contains("fedora directory") {
            return .directoryServer389
        }

        // 4. ApacheDS
        if vendor.contains("apache") {
            return .apacheDS
        }

        return .unknown
    }
}

// Minimal ordered-set helper to deduplicate controls while preserving insertion order.
private struct OrderedSet<Element: Hashable>: Sequence {
    private var seen = Set<Element>()
    private var elements = [Element]()

    init(_ source: some Sequence<Element>) {
        for element in source {
            if seen.insert(element).inserted {
                elements.append(element)
            }
        }
    }

    func makeIterator() -> IndexingIterator<[Element]> { elements.makeIterator() }
}
