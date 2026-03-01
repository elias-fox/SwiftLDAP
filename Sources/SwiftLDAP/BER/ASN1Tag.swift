/// ASN.1 tag definitions used by LDAP's BER encoding (ITU-T X.690).
///
/// LDAP messages are encoded using the Basic Encoding Rules (BER) of ASN.1.
/// Each element consists of a Tag-Length-Value (TLV) triplet.

/// The class of an ASN.1 tag, encoded in the two high bits of the tag byte.
public enum ASN1TagClass: UInt8, Sendable {
    /// Universal types defined by ASN.1 (e.g., INTEGER, OCTET STRING).
    case universal = 0x00
    /// Application-specific types (used extensively by LDAP protocol).
    case application = 0x40
    /// Context-specific types (used for CHOICE and OPTIONAL fields).
    case contextSpecific = 0x80
    /// Private types.
    case `private` = 0xC0
}

/// Identifies an ASN.1 element's type and encoding.
///
/// A tag consists of a class, a constructed/primitive bit, and a tag number.
/// For tag numbers 0–30 the tag fits in a single byte; higher numbers use
/// the long-form encoding (multi-byte tag), though LDAP stays within 0–30.
public struct ASN1Tag: Equatable, Hashable, Sendable {
    /// Raw tag byte value.
    public let rawValue: UInt8

    /// The class of this tag.
    public var tagClass: ASN1TagClass {
        ASN1TagClass(rawValue: rawValue & 0xC0)!
    }

    /// Whether the content is constructed (contains other TLV elements)
    /// rather than primitive.
    public var isConstructed: Bool {
        rawValue & 0x20 != 0
    }

    /// The tag number within its class (bits 0–4).
    public var tagNumber: UInt8 {
        rawValue & 0x1F
    }

    /// Creates a tag from a raw byte value.
    public init(rawValue: UInt8) {
        self.rawValue = rawValue
    }

    /// Creates a tag from its components.
    public init(class tagClass: ASN1TagClass, constructed: Bool, number: UInt8) {
        precondition(number <= 30, "Tag numbers > 30 require long-form encoding")
        self.rawValue = tagClass.rawValue | (constructed ? 0x20 : 0) | number
    }

    // MARK: - Universal Tags

    /// BOOLEAN (tag 1)
    public static let boolean = ASN1Tag(rawValue: 0x01)
    /// INTEGER (tag 2)
    public static let integer = ASN1Tag(rawValue: 0x02)
    /// OCTET STRING (tag 4) — primitive
    public static let octetString = ASN1Tag(rawValue: 0x04)
    /// NULL (tag 5)
    public static let null = ASN1Tag(rawValue: 0x05)
    /// ENUMERATED (tag 10)
    public static let enumerated = ASN1Tag(rawValue: 0x0A)
    /// SEQUENCE (tag 16, constructed)
    public static let sequence = ASN1Tag(rawValue: 0x30)
    /// SET (tag 17, constructed)
    public static let set = ASN1Tag(rawValue: 0x31)

    // MARK: - LDAP Application Tags (RFC 4511 Section 4.2)

    /// BindRequest (APPLICATION 0, constructed)
    public static let bindRequest = ASN1Tag(class: .application, constructed: true, number: 0)
    /// BindResponse (APPLICATION 1, constructed)
    public static let bindResponse = ASN1Tag(class: .application, constructed: true, number: 1)
    /// UnbindRequest (APPLICATION 2, primitive)
    public static let unbindRequest = ASN1Tag(class: .application, constructed: false, number: 2)
    /// SearchRequest (APPLICATION 3, constructed)
    public static let searchRequest = ASN1Tag(class: .application, constructed: true, number: 3)
    /// SearchResultEntry (APPLICATION 4, constructed)
    public static let searchResultEntry = ASN1Tag(class: .application, constructed: true, number: 4)
    /// SearchResultDone (APPLICATION 5, constructed)
    public static let searchResultDone = ASN1Tag(class: .application, constructed: true, number: 5)
    /// SearchResultReference (APPLICATION 19, constructed)
    public static let searchResultReference = ASN1Tag(class: .application, constructed: true, number: 19)
    /// ModifyRequest (APPLICATION 6, constructed)
    public static let modifyRequest = ASN1Tag(class: .application, constructed: true, number: 6)
    /// ModifyResponse (APPLICATION 7, constructed)
    public static let modifyResponse = ASN1Tag(class: .application, constructed: true, number: 7)
    /// AddRequest (APPLICATION 8, constructed)
    public static let addRequest = ASN1Tag(class: .application, constructed: true, number: 8)
    /// AddResponse (APPLICATION 9, constructed)
    public static let addResponse = ASN1Tag(class: .application, constructed: true, number: 9)
    /// DeleteRequest (APPLICATION 10, primitive)
    public static let deleteRequest = ASN1Tag(class: .application, constructed: false, number: 10)
    /// DeleteResponse (APPLICATION 11, constructed)
    public static let deleteResponse = ASN1Tag(class: .application, constructed: true, number: 11)
    /// ModifyDNRequest (APPLICATION 12, constructed)
    public static let modifyDNRequest = ASN1Tag(class: .application, constructed: true, number: 12)
    /// ModifyDNResponse (APPLICATION 13, constructed)
    public static let modifyDNResponse = ASN1Tag(class: .application, constructed: true, number: 13)
    /// CompareRequest (APPLICATION 14, constructed)
    public static let compareRequest = ASN1Tag(class: .application, constructed: true, number: 14)
    /// CompareResponse (APPLICATION 15, constructed)
    public static let compareResponse = ASN1Tag(class: .application, constructed: true, number: 15)
    /// AbandonRequest (APPLICATION 16, primitive)
    public static let abandonRequest = ASN1Tag(class: .application, constructed: false, number: 16)
    /// ExtendedRequest (APPLICATION 23, constructed)
    public static let extendedRequest = ASN1Tag(class: .application, constructed: true, number: 23)
    /// ExtendedResponse (APPLICATION 24, constructed)
    public static let extendedResponse = ASN1Tag(class: .application, constructed: true, number: 24)
    /// IntermediateResponse (APPLICATION 25, constructed)
    public static let intermediateResponse = ASN1Tag(class: .application, constructed: true, number: 25)

    // MARK: - Context-Specific Helpers

    /// Creates a context-specific primitive tag.
    public static func contextSpecific(_ number: UInt8) -> ASN1Tag {
        ASN1Tag(class: .contextSpecific, constructed: false, number: number)
    }

    /// Creates a context-specific constructed tag.
    public static func contextSpecificConstructed(_ number: UInt8) -> ASN1Tag {
        ASN1Tag(class: .contextSpecific, constructed: true, number: number)
    }
}
