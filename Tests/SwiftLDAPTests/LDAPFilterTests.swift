import Foundation
import Testing
@testable import SwiftLDAP

@Suite("LDAP Filter Tests")
struct LDAPFilterTests {

    // MARK: - Filter Parsing (RFC 4515)

    @Test("Parses equality filter")
    func parseEquality() throws {
        let filter = try LDAPFilter.parse("(cn=John Doe)")
        #expect(filter == .equalityMatch(attribute: "cn", value: Data("John Doe".utf8)))
    }

    @Test("Parses presence filter")
    func parsePresence() throws {
        let filter = try LDAPFilter.parse("(objectClass=*)")
        #expect(filter == .present(attribute: "objectClass"))
    }

    @Test("Parses AND filter")
    func parseAnd() throws {
        let filter = try LDAPFilter.parse("(&(cn=John)(sn=Doe))")
        if case .and(let filters) = filter {
            #expect(filters.count == 2)
            #expect(filters[0] == .equalityMatch(attribute: "cn", value: Data("John".utf8)))
            #expect(filters[1] == .equalityMatch(attribute: "sn", value: Data("Doe".utf8)))
        } else {
            Issue.record("Expected AND filter")
        }
    }

    @Test("Parses OR filter")
    func parseOr() throws {
        let filter = try LDAPFilter.parse("(|(cn=John)(cn=Jane))")
        if case .or(let filters) = filter {
            #expect(filters.count == 2)
        } else {
            Issue.record("Expected OR filter")
        }
    }

    @Test("Parses NOT filter")
    func parseNot() throws {
        let filter = try LDAPFilter.parse("(!(cn=John))")
        if case .not(let inner) = filter {
            #expect(inner == .equalityMatch(attribute: "cn", value: Data("John".utf8)))
        } else {
            Issue.record("Expected NOT filter")
        }
    }

    @Test("Parses greater-or-equal filter")
    func parseGreaterOrEqual() throws {
        let filter = try LDAPFilter.parse("(age>=21)")
        #expect(filter == .greaterOrEqual(attribute: "age", value: Data("21".utf8)))
    }

    @Test("Parses less-or-equal filter")
    func parseLessOrEqual() throws {
        let filter = try LDAPFilter.parse("(age<=65)")
        #expect(filter == .lessOrEqual(attribute: "age", value: Data("65".utf8)))
    }

    @Test("Parses approximate match filter")
    func parseApproxMatch() throws {
        let filter = try LDAPFilter.parse("(cn~=Jon)")
        #expect(filter == .approxMatch(attribute: "cn", value: Data("Jon".utf8)))
    }

    @Test("Parses substring filter with initial")
    func parseSubstringInitial() throws {
        let filter = try LDAPFilter.parse("(cn=John*)")
        if case .substrings(let attr, let initial, let any, let final_) = filter {
            #expect(attr == "cn")
            #expect(initial == Data("John".utf8))
            #expect(any.isEmpty)
            #expect(final_ == nil)
        } else {
            Issue.record("Expected substrings filter")
        }
    }

    @Test("Parses substring filter with final")
    func parseSubstringFinal() throws {
        let filter = try LDAPFilter.parse("(cn=*Doe)")
        if case .substrings(let attr, let initial, let any, let final_) = filter {
            #expect(attr == "cn")
            #expect(initial == nil)
            #expect(any.isEmpty)
            #expect(final_ == Data("Doe".utf8))
        } else {
            Issue.record("Expected substrings filter")
        }
    }

    @Test("Parses substring filter with initial, any, and final")
    func parseSubstringAll() throws {
        let filter = try LDAPFilter.parse("(cn=J*oh*n)")
        if case .substrings(let attr, let initial, let any, let final_) = filter {
            #expect(attr == "cn")
            #expect(initial == Data("J".utf8))
            #expect(any == [Data("oh".utf8)])
            #expect(final_ == Data("n".utf8))
        } else {
            Issue.record("Expected substrings filter")
        }
    }

    @Test("Parses complex nested filter")
    func parseComplex() throws {
        let filter = try LDAPFilter.parse("(&(objectClass=person)(|(cn=John*)(mail=*@example.com)))")
        if case .and(let filters) = filter {
            #expect(filters.count == 2)
            if case .or(let orFilters) = filters[1] {
                #expect(orFilters.count == 2)
            } else {
                Issue.record("Expected OR as second AND child")
            }
        } else {
            Issue.record("Expected AND filter")
        }
    }

    @Test("Parses filter with escaped characters")
    func parseEscaped() throws {
        let filter = try LDAPFilter.parse("(cn=John\\2a Doe)")
        // \2a = '*'
        if case .equalityMatch(_, let value) = filter {
            #expect(value == Data("John* Doe".utf8))
        } else {
            Issue.record("Expected equality match")
        }
    }

    @Test("Throws on invalid filter - missing parens")
    func invalidMissingParens() {
        #expect(throws: LDAPError.self) {
            try LDAPFilter.parse("cn=John")
        }
    }

    @Test("Throws on empty filter")
    func invalidEmpty() {
        #expect(throws: LDAPError.self) {
            try LDAPFilter.parse("")
        }
    }

    // MARK: - Filter BER Encoding

    @Test("Encodes presence filter")
    func encodePresence() {
        let filter = LDAPFilter.present(attribute: "cn")
        var encoder = BEREncoder()
        filter.encode(into: &encoder)
        let bytes = encoder.finish()
        // context-specific [7] primitive, "cn"
        #expect(bytes[0] == 0x87) // 0x80 | 7
        #expect(bytes[1] == 2)    // length of "cn"
    }

    @Test("Encodes equality filter")
    func encodeEquality() {
        let filter = LDAPFilter.equal("cn", "test")
        var encoder = BEREncoder()
        filter.encode(into: &encoder)
        let bytes = encoder.finish()
        // context-specific [3] constructed
        #expect(bytes[0] == 0xA3) // 0x80 | 0x20 | 3
    }

    @Test("Round-trips filter through BER encode/decode")
    func roundTripFilter() throws {
        let filter = LDAPFilter.and([
            .equal("objectClass", "person"),
            .present(attribute: "mail"),
            .not(.equal("cn", "admin")),
        ])

        var encoder = BEREncoder()
        filter.encode(into: &encoder)
        let bytes = encoder.finish()

        var decoder = BERDecoder(data: bytes)
        let element = try decoder.readElement()
        let decoded = try LDAPFilter.decode(from: element)

        #expect(decoded == filter)
    }

    @Test("Round-trips substring filter")
    func roundTripSubstring() throws {
        let filter = LDAPFilter.substrings(
            attribute: "cn",
            initial: Data("John".utf8),
            any: [Data("Q".utf8)],
            final: Data("Doe".utf8)
        )

        var encoder = BEREncoder()
        filter.encode(into: &encoder)
        let bytes = encoder.finish()

        var decoder = BERDecoder(data: bytes)
        let element = try decoder.readElement()
        let decoded = try LDAPFilter.decode(from: element)

        #expect(decoded == filter)
    }

    @Test("Round-trips greater-or-equal filter")
    func roundTripGte() throws {
        let filter = LDAPFilter.gte("age", "21")
        var encoder = BEREncoder()
        filter.encode(into: &encoder)
        let bytes = encoder.finish()
        var decoder = BERDecoder(data: bytes)
        let element = try decoder.readElement()
        let decoded = try LDAPFilter.decode(from: element)
        #expect(decoded == filter)
    }

    @Test("Round-trips extensible match filter")
    func roundTripExtensible() throws {
        let filter = LDAPFilter.extensibleMatch(
            matchingRule: "2.5.13.5",
            attribute: "cn",
            value: Data("test".utf8),
            dnAttributes: true
        )
        var encoder = BEREncoder()
        filter.encode(into: &encoder)
        let bytes = encoder.finish()
        var decoder = BERDecoder(data: bytes)
        let element = try decoder.readElement()
        let decoded = try LDAPFilter.decode(from: element)
        #expect(decoded == filter)
    }
}
