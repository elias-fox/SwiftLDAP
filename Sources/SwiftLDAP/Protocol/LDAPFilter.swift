import Foundation

/// An LDAP search filter (RFC 4511 §4.5.1, string representation in RFC 4515).
///
/// Filters are encoded as ASN.1 CHOICE types with context-specific tags.
public indirect enum LDAPFilter: Sendable, Equatable {
    /// AND of sub-filters: `(&(filter1)(filter2)...)`
    case and([LDAPFilter])
    /// OR of sub-filters: `(|(filter1)(filter2)...)`
    case or([LDAPFilter])
    /// NOT of a filter: `(!(filter))`
    case not(LDAPFilter)
    /// Equality match: `(attr=value)`
    case equalityMatch(attribute: String, value: Data)
    /// Substring match: `(attr=initial*any*...*final)`
    case substrings(attribute: String, initial: Data?, any: [Data], final: Data?)
    /// Greater-or-equal: `(attr>=value)`
    case greaterOrEqual(attribute: String, value: Data)
    /// Less-or-equal: `(attr<=value)`
    case lessOrEqual(attribute: String, value: Data)
    /// Presence test: `(attr=*)`
    case present(attribute: String)
    /// Approximate match: `(attr~=value)`
    case approxMatch(attribute: String, value: Data)
    /// Extensible match: `(attr:dn:oid:=value)` or `(:oid:=value)`
    case extensibleMatch(
        matchingRule: String?, attribute: String?, value: Data, dnAttributes: Bool
    )

    // MARK: - Convenience Initializers

    /// Creates an equality match filter with a string value.
    public static func equal(_ attribute: String, _ value: String) -> LDAPFilter {
        .equalityMatch(attribute: attribute, value: Data(value.utf8))
    }

    /// Creates a presence filter.
    public static func exists(_ attribute: String) -> LDAPFilter {
        .present(attribute: attribute)
    }

    /// Creates a substring filter from a pattern like "foo*bar*baz".
    public static func substring(_ attribute: String, _ pattern: String) -> LDAPFilter {
        let parts = pattern.split(separator: "*", omittingEmptySubsequences: false).map(String.init)
        let initial: Data? = parts.first.flatMap { $0.isEmpty ? nil : Data($0.utf8) }
        let final_: Data? = parts.last.flatMap { $0.isEmpty ? nil : Data($0.utf8) }
        let anyParts: [Data] = parts.count > 2
            ? parts[1..<(parts.count - 1)].compactMap { $0.isEmpty ? nil : Data($0.utf8) }
            : []
        return .substrings(attribute: attribute, initial: initial, any: anyParts, final: final_)
    }

    /// Creates a greater-or-equal filter with a string value.
    public static func gte(_ attribute: String, _ value: String) -> LDAPFilter {
        .greaterOrEqual(attribute: attribute, value: Data(value.utf8))
    }

    /// Creates a less-or-equal filter with a string value.
    public static func lte(_ attribute: String, _ value: String) -> LDAPFilter {
        .lessOrEqual(attribute: attribute, value: Data(value.utf8))
    }

    /// Creates an approximate match filter with a string value.
    public static func approx(_ attribute: String, _ value: String) -> LDAPFilter {
        .approxMatch(attribute: attribute, value: Data(value.utf8))
    }
}

// MARK: - Filter BER Encoding

extension LDAPFilter {
    /// Encodes this filter into BER using the context-specific tags
    /// defined in RFC 4511 §4.5.1:
    ///
    /// ```
    /// Filter ::= CHOICE {
    ///     and             [0] SET OF filter Filter,
    ///     or              [1] SET OF filter Filter,
    ///     not             [2] Filter,
    ///     equalityMatch   [3] AttributeValueAssertion,
    ///     substrings      [4] SubstringFilter,
    ///     greaterOrEqual  [5] AttributeValueAssertion,
    ///     lessOrEqual     [6] AttributeValueAssertion,
    ///     present         [7] AttributeDescription,
    ///     approxMatch     [8] AttributeValueAssertion,
    ///     extensibleMatch [9] MatchingRuleAssertion,
    /// }
    /// ```
    public func encode(into encoder: inout BEREncoder) {
        switch self {
        case .and(let filters):
            encoder.writeSequence(tag: .contextSpecificConstructed(0)) { sub in
                for filter in filters {
                    filter.encode(into: &sub)
                }
            }
        case .or(let filters):
            encoder.writeSequence(tag: .contextSpecificConstructed(1)) { sub in
                for filter in filters {
                    filter.encode(into: &sub)
                }
            }
        case .not(let filter):
            encoder.writeSequence(tag: .contextSpecificConstructed(2)) { sub in
                filter.encode(into: &sub)
            }
        case .equalityMatch(let attr, let value):
            encodeAttributeValueAssertion(tag: 3, attribute: attr, value: value, into: &encoder)
        case .substrings(let attr, let initial, let any, let final_):
            encoder.writeSequence(tag: .contextSpecificConstructed(4)) { sub in
                sub.writeOctetString(attr)
                sub.writeSequence { subSeq in
                    if let initial {
                        subSeq.writeOctetString(Array(initial), tag: .contextSpecific(0))
                    }
                    for part in any {
                        subSeq.writeOctetString(Array(part), tag: .contextSpecific(1))
                    }
                    if let final_ {
                        subSeq.writeOctetString(Array(final_), tag: .contextSpecific(2))
                    }
                }
            }
        case .greaterOrEqual(let attr, let value):
            encodeAttributeValueAssertion(tag: 5, attribute: attr, value: value, into: &encoder)
        case .lessOrEqual(let attr, let value):
            encodeAttributeValueAssertion(tag: 6, attribute: attr, value: value, into: &encoder)
        case .present(let attr):
            encoder.writeOctetString(attr, tag: .contextSpecific(7))
        case .approxMatch(let attr, let value):
            encodeAttributeValueAssertion(tag: 8, attribute: attr, value: value, into: &encoder)
        case .extensibleMatch(let matchingRule, let attr, let value, let dnAttributes):
            encoder.writeSequence(tag: .contextSpecificConstructed(9)) { sub in
                if let matchingRule {
                    sub.writeOctetString(matchingRule, tag: .contextSpecific(1))
                }
                if let attr {
                    sub.writeOctetString(attr, tag: .contextSpecific(2))
                }
                sub.writeOctetString(Array(value), tag: .contextSpecific(3))
                if dnAttributes {
                    sub.writeBoolean(true, tag: .contextSpecific(4))
                }
            }
        }
    }

    private func encodeAttributeValueAssertion(
        tag: UInt8, attribute: String, value: Data, into encoder: inout BEREncoder
    ) {
        encoder.writeSequence(tag: .contextSpecificConstructed(tag)) { sub in
            sub.writeOctetString(attribute)
            sub.writeOctetString(Array(value))
        }
    }
}

// MARK: - Filter BER Decoding

extension LDAPFilter {
    /// Decodes a filter from a BER element.
    public static func decode(from element: BERElement) throws -> LDAPFilter {
        let tag = element.tag
        let tagNumber = tag.tagNumber

        switch (tag.tagClass, tag.isConstructed, tagNumber) {
        case (.contextSpecific, true, 0): // AND
            var sub = element.constructedDecoder()
            var filters: [LDAPFilter] = []
            while sub.hasMore {
                let child = try sub.readElement()
                filters.append(try LDAPFilter.decode(from: child))
            }
            return .and(filters)

        case (.contextSpecific, true, 1): // OR
            var sub = element.constructedDecoder()
            var filters: [LDAPFilter] = []
            while sub.hasMore {
                let child = try sub.readElement()
                filters.append(try LDAPFilter.decode(from: child))
            }
            return .or(filters)

        case (.contextSpecific, true, 2): // NOT
            var sub = element.constructedDecoder()
            let child = try sub.readElement()
            return .not(try LDAPFilter.decode(from: child))

        case (.contextSpecific, true, 3): // equalityMatch
            let (attr, value) = try decodeAttributeValueAssertion(element)
            return .equalityMatch(attribute: attr, value: value)

        case (.contextSpecific, true, 4): // substrings
            var sub = element.constructedDecoder()
            let attr = try sub.readString()
            var seqDecoder = try sub.readSequence()
            var initial: Data?
            var anyParts: [Data] = []
            var final_: Data?
            while seqDecoder.hasMore {
                let part = try seqDecoder.readElement()
                switch part.tag.tagNumber {
                case 0: initial = Data(part.octetBytes())
                case 1: anyParts.append(Data(part.octetBytes()))
                case 2: final_ = Data(part.octetBytes())
                default: throw BERDecodingError.invalidData("Unknown substring choice tag")
                }
            }
            return .substrings(attribute: attr, initial: initial, any: anyParts, final: final_)

        case (.contextSpecific, true, 5): // greaterOrEqual
            let (attr, value) = try decodeAttributeValueAssertion(element)
            return .greaterOrEqual(attribute: attr, value: value)

        case (.contextSpecific, true, 6): // lessOrEqual
            let (attr, value) = try decodeAttributeValueAssertion(element)
            return .lessOrEqual(attribute: attr, value: value)

        case (.contextSpecific, false, 7): // present
            return .present(attribute: element.stringValue())

        case (.contextSpecific, true, 8): // approxMatch
            let (attr, value) = try decodeAttributeValueAssertion(element)
            return .approxMatch(attribute: attr, value: value)

        case (.contextSpecific, true, 9): // extensibleMatch
            var sub = element.constructedDecoder()
            var matchingRule: String?
            var attribute: String?
            var value: Data = Data()
            var dnAttributes = false
            while sub.hasMore {
                let part = try sub.readElement()
                switch part.tag.tagNumber {
                case 1: matchingRule = part.stringValue()
                case 2: attribute = part.stringValue()
                case 3: value = Data(part.octetBytes())
                case 4: dnAttributes = (try? part.booleanValue()) ?? false
                default: break
                }
            }
            return .extensibleMatch(
                matchingRule: matchingRule, attribute: attribute,
                value: value, dnAttributes: dnAttributes
            )

        default:
            throw BERDecodingError.invalidData(
                "Unknown filter tag: class=\(tag.tagClass) constructed=\(tag.isConstructed) number=\(tagNumber)"
            )
        }
    }

    private static func decodeAttributeValueAssertion(
        _ element: BERElement
    ) throws -> (String, Data) {
        var sub = element.constructedDecoder()
        let attr = try sub.readString()
        let value = try sub.readOctetString()
        return (attr, Data(value))
    }
}

// MARK: - RFC 4515 String Filter Parser

extension LDAPFilter {
    /// Parses an LDAP filter from its RFC 4515 string representation.
    ///
    /// Examples:
    /// - `(cn=John Doe)`
    /// - `(&(objectClass=person)(mail=*))`
    /// - `(|(cn=John*)(cn=Jane*))`
    /// - `(!(userAccountControl:1.2.840.113556.1.4.803:=2))`
    public static func parse(_ string: String) throws -> LDAPFilter {
        var parser = FilterParser(string)
        let filter = try parser.parseFilter()
        guard parser.isAtEnd else {
            throw LDAPError.invalidFilter("Unexpected trailing content: \(parser.remaining)")
        }
        return filter
    }
}

/// A recursive-descent parser for RFC 4515 LDAP search filter strings.
private struct FilterParser {
    private let chars: [Character]
    private var index: Int

    init(_ string: String) {
        self.chars = Array(string)
        self.index = 0
    }

    var isAtEnd: Bool { index >= chars.count }
    var remaining: String { String(chars[index...]) }

    // MARK: - Parsing

    mutating func parseFilter() throws -> LDAPFilter {
        try expect("(")
        let filter = try parseFilterComp()
        try expect(")")
        return filter
    }

    private mutating func parseFilterComp() throws -> LDAPFilter {
        guard !isAtEnd else {
            throw LDAPError.invalidFilter("Unexpected end of filter")
        }
        switch chars[index] {
        case "&":
            index += 1
            return try .and(parseFilterList())
        case "|":
            index += 1
            return try .or(parseFilterList())
        case "!":
            index += 1
            return try .not(parseFilter())
        default:
            return try parseItem()
        }
    }

    private mutating func parseFilterList() throws -> [LDAPFilter] {
        var filters: [LDAPFilter] = []
        while !isAtEnd && chars[index] == "(" {
            filters.append(try parseFilter())
        }
        if filters.isEmpty {
            throw LDAPError.invalidFilter("Filter list must contain at least one filter")
        }
        return filters
    }

    private mutating func parseItem() throws -> LDAPFilter {
        let attr = try parseAttributeDescription()

        guard !isAtEnd else {
            throw LDAPError.invalidFilter("Expected filter type after attribute")
        }

        // Check for extensible match: attr:dn:rule:=value or :rule:=value
        if chars[index] == ":" {
            return try parseExtensibleMatch(attribute: attr)
        }

        let filterType = try parseFilterType()
        let valueStr = try parseAssertionValue()

        switch filterType {
        case .equal:
            // Check for presence: (attr=*)
            if valueStr == "*" {
                return .present(attribute: attr)
            }
            // Check for substring: value contains unescaped *
            if valueStr.contains("*") {
                return parseSubstringFilter(attribute: attr, value: valueStr)
            }
            return .equalityMatch(attribute: attr, value: decodeFilterValue(valueStr))
        case .approx:
            return .approxMatch(attribute: attr, value: decodeFilterValue(valueStr))
        case .greaterOrEqual:
            return .greaterOrEqual(attribute: attr, value: decodeFilterValue(valueStr))
        case .lessOrEqual:
            return .lessOrEqual(attribute: attr, value: decodeFilterValue(valueStr))
        }
    }

    private mutating func parseExtensibleMatch(attribute: String) throws -> LDAPFilter {
        // Format: attr:dn:matchingRule:=value or attr::=value etc.
        var dnAttributes = false
        var matchingRule: String?
        let attr: String? = attribute.isEmpty ? nil : attribute

        // Parse colon-separated components
        while !isAtEnd && chars[index] == ":" {
            index += 1  // consume ':'
            if !isAtEnd && chars[index] == "=" {
                index += 1  // consume '='
                break
            }
            let component = parseUntil { $0 == ":" || $0 == "=" }
            if component.lowercased() == "dn" {
                dnAttributes = true
            } else {
                matchingRule = component
            }
        }

        let value = try parseAssertionValue()
        return .extensibleMatch(
            matchingRule: matchingRule,
            attribute: attr,
            value: decodeFilterValue(value),
            dnAttributes: dnAttributes
        )
    }

    private func parseSubstringFilter(attribute: String, value: String) -> LDAPFilter {
        let parts = value.split(separator: "*", omittingEmptySubsequences: false).map(String.init)
        let initial: Data? = parts.first.flatMap { $0.isEmpty ? nil : decodeFilterValue($0) }
        let final_: Data? = parts.last.flatMap { $0.isEmpty ? nil : decodeFilterValue($0) }
        let anyParts: [Data] = parts.count > 2
            ? parts[1..<(parts.count - 1)].compactMap {
                $0.isEmpty ? nil : decodeFilterValue($0)
            }
            : []
        return .substrings(attribute: attribute, initial: initial, any: anyParts, final: final_)
    }

    // MARK: - Lexer Helpers

    private mutating func parseAttributeDescription() throws -> String {
        parseUntil { $0 == "=" || $0 == "~" || $0 == ">" || $0 == "<" || $0 == ":" || $0 == ")" }
    }

    private enum FilterType {
        case equal, approx, greaterOrEqual, lessOrEqual
    }

    private mutating func parseFilterType() throws -> FilterType {
        guard !isAtEnd else {
            throw LDAPError.invalidFilter("Expected filter operator")
        }
        switch chars[index] {
        case "=":
            index += 1
            return .equal
        case "~":
            index += 1
            try expect("=")
            return .approx
        case ">":
            index += 1
            try expect("=")
            return .greaterOrEqual
        case "<":
            index += 1
            try expect("=")
            return .lessOrEqual
        default:
            throw LDAPError.invalidFilter("Unexpected filter operator: \(chars[index])")
        }
    }

    private mutating func parseAssertionValue() throws -> String {
        parseUntil { $0 == ")" }
    }

    private mutating func parseUntil(_ predicate: (Character) -> Bool) -> String {
        var result: [Character] = []
        while !isAtEnd && !predicate(chars[index]) {
            result.append(chars[index])
            index += 1
        }
        return String(result)
    }

    private mutating func expect(_ char: Character) throws {
        guard !isAtEnd && chars[index] == char else {
            let found = isAtEnd ? "end of input" : String(chars[index])
            throw LDAPError.invalidFilter("Expected '\(char)' but found '\(found)'")
        }
        index += 1
    }

    // MARK: - Value Decoding

    /// Decodes RFC 4515 escaped values (e.g., `\2a` → `*`).
    private func decodeFilterValue(_ string: String) -> Data {
        var bytes: [UInt8] = []
        var chars = Array(string)
        var i = 0
        while i < chars.count {
            if chars[i] == "\\" && i + 2 < chars.count {
                let hex = String(chars[(i + 1)...(i + 2)])
                if let byte = UInt8(hex, radix: 16) {
                    bytes.append(byte)
                    i += 3
                    continue
                }
            }
            for byte in String(chars[i]).utf8 {
                bytes.append(byte)
            }
            i += 1
        }
        return Data(bytes)
    }
}
