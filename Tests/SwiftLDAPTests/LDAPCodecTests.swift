import Foundation
import Testing
@testable import SwiftLDAP

@Suite("LDAP Codec Tests")
struct LDAPCodecTests {

    // MARK: - Bind Request Encoding

    @Test("Encodes simple bind request")
    func encodeSimpleBind() throws {
        let bytes = LDAPCodec.encode(
            messageID: 1,
            operation: .bindRequest(
                version: 3,
                name: "cn=admin,dc=example,dc=com",
                authentication: .simple(password: "secret")
            )
        )

        // Verify it's a valid SEQUENCE
        #expect(bytes[0] == 0x30) // SEQUENCE tag

        // The codec only decodes responses (server→client), so verify the
        // request encoding by manually parsing the BER structure.
        var outer = BERDecoder(data: bytes)
        var seq = try outer.readSequence()
        let id = try seq.readInt32()
        #expect(id == 1)

        // Check the bind request tag
        let bindElement = try seq.readElement()
        #expect(bindElement.tag == .bindRequest)
    }

    @Test("Encodes SASL bind request")
    func encodeSASLBind() throws {
        let bytes = LDAPCodec.encode(
            messageID: 2,
            operation: .bindRequest(
                version: 3,
                name: "",
                authentication: .sasl(mechanism: "EXTERNAL", credentials: nil)
            )
        )

        var outer = BERDecoder(data: bytes)
        var seq = try outer.readSequence()
        let id = try seq.readInt32()
        #expect(id == 2)
        let bindElement = try seq.readElement()
        #expect(bindElement.tag == .bindRequest)
    }

    // MARK: - Search Request Encoding

    @Test("Encodes search request")
    func encodeSearchRequest() throws {
        let bytes = LDAPCodec.encode(
            messageID: 3,
            operation: .searchRequest(SearchParameters(
                baseDN: "dc=example,dc=com",
                scope: .wholeSubtree,
                filter: .equal("cn", "test"),
                attributes: ["cn", "mail"]
            ))
        )

        var outer = BERDecoder(data: bytes)
        var seq = try outer.readSequence()
        let id = try seq.readInt32()
        #expect(id == 3)
        let searchElement = try seq.readElement()
        #expect(searchElement.tag == .searchRequest)
    }

    // MARK: - Modify Request Encoding

    @Test("Encodes modify request")
    func encodeModifyRequest() throws {
        let bytes = LDAPCodec.encode(
            messageID: 4,
            operation: .modifyRequest(
                dn: "cn=test,dc=example,dc=com",
                modifications: [
                    ModifyItem(
                        operation: .replace,
                        attribute: LDAPAttribute(type: "mail", stringValues: ["new@example.com"])
                    ),
                ]
            )
        )

        var outer = BERDecoder(data: bytes)
        var seq = try outer.readSequence()
        _ = try seq.readInt32()
        let modElement = try seq.readElement()
        #expect(modElement.tag == .modifyRequest)
    }

    // MARK: - Add Request Encoding

    @Test("Encodes add request")
    func encodeAddRequest() throws {
        let bytes = LDAPCodec.encode(
            messageID: 5,
            operation: .addRequest(
                dn: "cn=new,dc=example,dc=com",
                attributes: [
                    LDAPAttribute(type: "objectClass", stringValues: ["top", "person"]),
                    LDAPAttribute(type: "cn", stringValues: ["new"]),
                ]
            )
        )

        var outer = BERDecoder(data: bytes)
        var seq = try outer.readSequence()
        _ = try seq.readInt32()
        let addElement = try seq.readElement()
        #expect(addElement.tag == .addRequest)
    }

    // MARK: - Delete Request Encoding

    @Test("Encodes delete request")
    func encodeDeleteRequest() throws {
        let bytes = LDAPCodec.encode(
            messageID: 6,
            operation: .deleteRequest(dn: "cn=old,dc=example,dc=com")
        )

        var outer = BERDecoder(data: bytes)
        var seq = try outer.readSequence()
        let id = try seq.readInt32()
        #expect(id == 6)
        let delElement = try seq.readElement()
        #expect(delElement.tag == .deleteRequest)
    }

    // MARK: - ModifyDN Request Encoding

    @Test("Encodes modify DN request")
    func encodeModifyDN() throws {
        let bytes = LDAPCodec.encode(
            messageID: 7,
            operation: .modifyDNRequest(
                dn: "cn=old,dc=example,dc=com",
                newRDN: "cn=new",
                deleteOldRDN: true,
                newSuperior: "ou=people,dc=example,dc=com"
            )
        )

        var outer = BERDecoder(data: bytes)
        var seq = try outer.readSequence()
        _ = try seq.readInt32()
        let mdnElement = try seq.readElement()
        #expect(mdnElement.tag == .modifyDNRequest)
    }

    // MARK: - Compare Request Encoding

    @Test("Encodes compare request")
    func encodeCompareRequest() throws {
        let bytes = LDAPCodec.encode(
            messageID: 8,
            operation: .compareRequest(
                dn: "cn=test,dc=example,dc=com",
                attributeDescription: "userPassword",
                assertionValue: Data("secret".utf8)
            )
        )

        var outer = BERDecoder(data: bytes)
        var seq = try outer.readSequence()
        _ = try seq.readInt32()
        let cmpElement = try seq.readElement()
        #expect(cmpElement.tag == .compareRequest)
    }

    // MARK: - Abandon Request Encoding

    @Test("Encodes abandon request")
    func encodeAbandonRequest() throws {
        let bytes = LDAPCodec.encode(
            messageID: 9,
            operation: .abandonRequest(messageID: 3)
        )

        var outer = BERDecoder(data: bytes)
        var seq = try outer.readSequence()
        let id = try seq.readInt32()
        #expect(id == 9)
        let abandonElement = try seq.readElement()
        #expect(abandonElement.tag == .abandonRequest)
    }

    // MARK: - Extended Request Encoding

    @Test("Encodes extended request (StartTLS)")
    func encodeExtendedRequest() throws {
        let bytes = LDAPCodec.encode(
            messageID: 10,
            operation: .extendedRequest(oid: "1.3.6.1.4.1.1466.20037", value: nil)
        )

        var outer = BERDecoder(data: bytes)
        var seq = try outer.readSequence()
        _ = try seq.readInt32()
        let extElement = try seq.readElement()
        #expect(extElement.tag == .extendedRequest)
    }

    // MARK: - Response Decoding

    @Test("Decodes bind response (success)")
    func decodeBindResponse() throws {
        // Build a mock BindResponse
        var encoder = BEREncoder()
        encoder.writeSequence { seq in
            seq.writeInteger(1)
            seq.writeSequence(tag: .bindResponse) { bind in
                bind.writeEnumerated(0) // success
                bind.writeOctetString("") // matchedDN
                bind.writeOctetString("") // diagnosticMessage
            }
        }
        let bytes = encoder.finish()

        let (msgID, op, _) = try LDAPCodec.decode(bytes)
        #expect(msgID == 1)
        if case .bindResponse(let result, let creds) = op {
            #expect(result.resultCode == .success)
            #expect(result.matchedDN == "")
            #expect(result.diagnosticMessage == "")
            #expect(creds == nil)
        } else {
            Issue.record("Expected BindResponse")
        }
    }

    @Test("Decodes bind response (invalid credentials)")
    func decodeBindResponseError() throws {
        var encoder = BEREncoder()
        encoder.writeSequence { seq in
            seq.writeInteger(1)
            seq.writeSequence(tag: .bindResponse) { bind in
                bind.writeEnumerated(49) // invalidCredentials
                bind.writeOctetString("")
                bind.writeOctetString("Invalid DN or password")
            }
        }
        let bytes = encoder.finish()

        let (_, op, _) = try LDAPCodec.decode(bytes)
        if case .bindResponse(let result, _) = op {
            #expect(result.resultCode == .invalidCredentials)
            #expect(result.diagnosticMessage == "Invalid DN or password")
        } else {
            Issue.record("Expected BindResponse")
        }
    }

    @Test("Decodes search result entry")
    func decodeSearchResultEntry() throws {
        var encoder = BEREncoder()
        encoder.writeSequence { seq in
            seq.writeInteger(2)
            seq.writeSequence(tag: .searchResultEntry) { entry in
                entry.writeOctetString("cn=John,dc=example,dc=com")
                entry.writeSequence { attrs in
                    // Attribute: cn
                    attrs.writeSequence { partial in
                        partial.writeOctetString("cn")
                        partial.writeSet { vals in
                            vals.writeOctetString("John")
                        }
                    }
                    // Attribute: mail
                    attrs.writeSequence { partial in
                        partial.writeOctetString("mail")
                        partial.writeSet { vals in
                            vals.writeOctetString("john@example.com")
                        }
                    }
                }
            }
        }
        let bytes = encoder.finish()

        let (msgID, op, _) = try LDAPCodec.decode(bytes)
        #expect(msgID == 2)
        if case .searchResultEntry(let entry) = op {
            #expect(entry.dn == "cn=John,dc=example,dc=com")
            #expect(entry.stringValues(for: "cn") == ["John"])
            #expect(entry.stringValues(for: "mail") == ["john@example.com"])
        } else {
            Issue.record("Expected SearchResultEntry")
        }
    }

    @Test("Decodes search result done")
    func decodeSearchResultDone() throws {
        var encoder = BEREncoder()
        encoder.writeSequence { seq in
            seq.writeInteger(2)
            seq.writeSequence(tag: .searchResultDone) { done in
                done.writeEnumerated(0)
                done.writeOctetString("")
                done.writeOctetString("")
            }
        }
        let bytes = encoder.finish()

        let (_, op, _) = try LDAPCodec.decode(bytes)
        if case .searchResultDone(let result) = op {
            #expect(result.resultCode == .success)
        } else {
            Issue.record("Expected SearchResultDone")
        }
    }

    @Test("Decodes modify response")
    func decodeModifyResponse() throws {
        var encoder = BEREncoder()
        encoder.writeSequence { seq in
            seq.writeInteger(3)
            seq.writeSequence(tag: .modifyResponse) { resp in
                resp.writeEnumerated(0)
                resp.writeOctetString("")
                resp.writeOctetString("")
            }
        }
        let bytes = encoder.finish()

        let (_, op, _) = try LDAPCodec.decode(bytes)
        if case .modifyResponse(let result) = op {
            #expect(result.resultCode == .success)
        } else {
            Issue.record("Expected ModifyResponse")
        }
    }

    @Test("Decodes extended response")
    func decodeExtendedResponse() throws {
        var encoder = BEREncoder()
        encoder.writeSequence { seq in
            seq.writeInteger(5)
            seq.writeSequence(tag: .extendedResponse) { ext in
                ext.writeEnumerated(0)
                ext.writeOctetString("")
                ext.writeOctetString("")
                ext.writeOctetString("1.2.3.4", tag: .contextSpecific(10))
                ext.writeOctetString("response-data", tag: .contextSpecific(11))
            }
        }
        let bytes = encoder.finish()

        let (_, op, _) = try LDAPCodec.decode(bytes)
        if case .extendedResponse(let result, let oid, let value) = op {
            #expect(result.resultCode == .success)
            #expect(oid == "1.2.3.4")
            #expect(value == Data("response-data".utf8))
        } else {
            Issue.record("Expected ExtendedResponse")
        }
    }

    // MARK: - Controls

    @Test("Encodes and decodes controls")
    func roundTripControls() throws {
        let controls = [
            LDAPControl(oid: "1.2.3.4.5", criticality: true, value: Data("ctrl-value".utf8)),
            LDAPControl(oid: "2.3.4.5.6", criticality: false, value: nil),
        ]

        let bytes = LDAPCodec.encode(
            messageID: 1,
            operation: .unbindRequest,
            controls: controls
        )

        // The unbind doesn't produce a response, but let's verify the encoding structure
        var outer = BERDecoder(data: bytes)
        var seq = try outer.readSequence()
        _ = try seq.readInt32()
        _ = try seq.readElement() // unbind
        // Controls should follow
        if seq.hasMore {
            let ctrlsElement = try seq.readElement(expectedTag: .contextSpecificConstructed(0))
            var ctrlsDecoder = ctrlsElement.constructedDecoder()
            var decodedControls: [LDAPControl] = []

            while ctrlsDecoder.hasMore {
                var ctrlDecoder = try ctrlsDecoder.readSequence()
                let oid = try ctrlDecoder.readString()
                var criticality = false
                var value: Data?

                while ctrlDecoder.hasMore {
                    let nextTag = try ctrlDecoder.peekTag()
                    if nextTag == .boolean {
                        criticality = try ctrlDecoder.readBoolean()
                    } else if nextTag == .octetString {
                        value = Data(try ctrlDecoder.readOctetString())
                    } else {
                        try ctrlDecoder.skipElement()
                    }
                }
                decodedControls.append(
                    LDAPControl(oid: oid, criticality: criticality, value: value))
            }

            #expect(decodedControls.count == 2)
            #expect(decodedControls[0].oid == "1.2.3.4.5")
            #expect(decodedControls[0].criticality == true)
            #expect(decodedControls[0].value == Data("ctrl-value".utf8))
            #expect(decodedControls[1].oid == "2.3.4.5.6")
            #expect(decodedControls[1].criticality == false)
            #expect(decodedControls[1].value == nil)
        } else {
            Issue.record("Expected controls in encoding")
        }
    }

    // MARK: - Message Envelope

    @Test("Decodes LDAP message envelope helper")
    func decodeEnvelope() throws {
        var encoder = BEREncoder()
        encoder.writeSequence { seq in
            seq.writeInteger(42)
            seq.writeSequence(tag: .searchResultDone) { done in
                done.writeEnumerated(0)
                done.writeOctetString("")
                done.writeOctetString("")
            }
        }
        let bytes = encoder.finish()

        let (msgID, _, _) = try LDAPCodec.decode(bytes)
        #expect(msgID == 42)
    }

    // MARK: - Search Result Reference

    @Test("Decodes search result reference")
    func decodeSearchResultReference() throws {
        var encoder = BEREncoder()
        encoder.writeSequence { seq in
            seq.writeInteger(2)
            seq.writeSequence(tag: .searchResultReference) { ref in
                ref.writeOctetString("ldap://other.example.com/dc=example,dc=com")
            }
        }
        let bytes = encoder.finish()

        let (_, op, _) = try LDAPCodec.decode(bytes)
        if case .searchResultReference(let uris) = op {
            #expect(uris.count == 1)
            #expect(uris[0] == "ldap://other.example.com/dc=example,dc=com")
        } else {
            Issue.record("Expected SearchResultReference")
        }
    }

    // MARK: - Security Guards

    @Test("Throws when LDAPResult contains too many referrals")
    func decodeResultWithTooManyReferrals() {
        var encoder = BEREncoder()
        encoder.writeSequence { seq in
            seq.writeInteger(1)
            seq.writeSequence(tag: .searchResultDone) { done in
                done.writeEnumerated(10) // referral
                done.writeOctetString("")
                done.writeOctetString("")
                done.writeSequence(tag: .contextSpecificConstructed(3)) { refs in
                    for i in 0..<101 {
                        refs.writeOctetString("ldap://ref\(i).example.com/")
                    }
                }
            }
        }
        let bytes = encoder.finish()
        #expect(throws: BERDecodingError.self) {
            try LDAPCodec.decode(bytes)
        }
    }

    @Test("Throws when searchResultReference contains too many URIs")
    func decodeSearchResultReferenceOverflow() {
        var encoder = BEREncoder()
        encoder.writeSequence { seq in
            seq.writeInteger(2)
            seq.writeSequence(tag: .searchResultReference) { ref in
                for i in 0..<101 {
                    ref.writeOctetString("ldap://ref\(i).example.com/")
                }
            }
        }
        let bytes = encoder.finish()
        #expect(throws: BERDecodingError.self) {
            try LDAPCodec.decode(bytes)
        }
    }

    @Test("Throws when message contains too many controls")
    func decodeMessageWithTooManyControls() {
        var encoder = BEREncoder()
        encoder.writeSequence { seq in
            seq.writeInteger(1)
            seq.writeSequence(tag: .bindResponse) { bind in
                bind.writeEnumerated(0) // success
                bind.writeOctetString("")
                bind.writeOctetString("")
            }
            seq.writeSequence(tag: .contextSpecificConstructed(0)) { ctrls in
                for i in 0..<101 {
                    ctrls.writeSequence { ctrl in
                        ctrl.writeOctetString("1.2.3.\(i)")
                    }
                }
            }
        }
        let bytes = encoder.finish()
        #expect(throws: BERDecodingError.self) {
            try LDAPCodec.decode(bytes)
        }
    }

    // MARK: - LDAPResult with Referrals

    @Test("Decodes result with referrals")
    func decodeResultWithReferrals() throws {
        var encoder = BEREncoder()
        encoder.writeSequence { seq in
            seq.writeInteger(1)
            seq.writeSequence(tag: .searchResultDone) { done in
                done.writeEnumerated(10) // referral
                done.writeOctetString("")
                done.writeOctetString("")
                done.writeSequence(tag: .contextSpecificConstructed(3)) { refs in
                    refs.writeOctetString("ldap://ref1.example.com/")
                    refs.writeOctetString("ldap://ref2.example.com/")
                }
            }
        }
        let bytes = encoder.finish()

        let (_, op, _) = try LDAPCodec.decode(bytes)
        if case .searchResultDone(let result) = op {
            #expect(result.resultCode == .referral)
            #expect(result.referrals.count == 2)
        } else {
            Issue.record("Expected SearchResultDone")
        }
    }
}
