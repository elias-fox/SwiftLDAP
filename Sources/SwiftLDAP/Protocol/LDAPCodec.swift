import Foundation

/// Encodes and decodes LDAP protocol messages to/from BER.
///
/// Each LDAP message is a SEQUENCE containing:
/// 1. MessageID (INTEGER)
/// 2. Protocol operation (APPLICATION-tagged)
/// 3. Optional controls (context-specific [0])
///
/// Per RFC 4511 §4.2.
public enum LDAPCodec {

    // MARK: - Limits

    private static let maxReferrals = 100
    private static let maxControls = 100

    // MARK: - Encoding

    /// Encodes a complete LDAP message.
    public static func encode(
        messageID: Int32,
        operation: LDAPOperation,
        controls: [LDAPControl] = []
    ) -> [UInt8] {
        var encoder = BEREncoder()
        encoder.writeSequence { seq in
            seq.writeInteger(messageID)
            encodeOperation(operation, into: &seq)
            if !controls.isEmpty {
                encodeControls(controls, into: &seq)
            }
        }
        return encoder.finish()
    }

    /// Encodes just the protocol operation.
    static func encodeOperation(_ operation: LDAPOperation, into encoder: inout BEREncoder) {
        switch operation {
        case .bindRequest(let version, let name, let auth):
            encodeBindRequest(version: version, name: name, auth: auth, into: &encoder)
        case .unbindRequest:
            encoder.writeNull(tag: .unbindRequest)
        case .searchRequest(let params):
            encodeSearchRequest(params, into: &encoder)
        case .modifyRequest(let dn, let mods):
            encodeModifyRequest(dn: dn, modifications: mods, into: &encoder)
        case .addRequest(let dn, let attrs):
            encodeAddRequest(dn: dn, attributes: attrs, into: &encoder)
        case .deleteRequest(let dn):
            encoder.writeOctetString(dn, tag: .deleteRequest)
        case .modifyDNRequest(let dn, let newRDN, let deleteOldRDN, let newSuperior):
            encodeModifyDNRequest(
                dn: dn, newRDN: newRDN,
                deleteOldRDN: deleteOldRDN, newSuperior: newSuperior,
                into: &encoder
            )
        case .compareRequest(let dn, let attrDesc, let value):
            encodeCompareRequest(dn: dn, attribute: attrDesc, value: value, into: &encoder)
        case .abandonRequest(let id):
            encoder.writeInteger(Int(id), tag: .abandonRequest)
        case .extendedRequest(let oid, let value):
            encodeExtendedRequest(oid: oid, value: value, into: &encoder)
        default:
            // Response types are decoded, not encoded by the client.
            break
        }
    }

    // MARK: - Request Encoding Helpers

    private static func encodeBindRequest(
        version: Int, name: String, auth: BindAuthentication, into encoder: inout BEREncoder
    ) {
        encoder.writeSequence(tag: .bindRequest) { bind in
            bind.writeInteger(version)
            bind.writeOctetString(name)
            switch auth {
            case .simple(let password):
                // Simple auth: context [0] primitive OCTET STRING
                bind.writeOctetString(password, tag: .contextSpecific(0))
            case .sasl(let mechanism, let credentials):
                // SASL auth: context [3] constructed { mechanism, [credentials] }
                bind.writeSequence(tag: .contextSpecificConstructed(3)) { sasl in
                    sasl.writeOctetString(mechanism)
                    if let creds = credentials {
                        sasl.writeOctetString(Array(creds))
                    }
                }
            }
        }
    }

    private static func encodeSearchRequest(
        _ params: SearchParameters, into encoder: inout BEREncoder
    ) {
        encoder.writeSequence(tag: .searchRequest) { search in
            search.writeOctetString(params.baseDN)
            search.writeEnumerated(params.scope.rawValue)
            search.writeEnumerated(params.derefAliases.rawValue)
            search.writeInteger(params.sizeLimit)
            search.writeInteger(params.timeLimit)
            search.writeBoolean(params.typesOnly)
            params.filter.encode(into: &search)
            search.writeSequence { attrs in
                for attr in params.attributes {
                    attrs.writeOctetString(attr)
                }
            }
        }
    }

    private static func encodeModifyRequest(
        dn: String, modifications: [ModifyItem], into encoder: inout BEREncoder
    ) {
        encoder.writeSequence(tag: .modifyRequest) { mod in
            mod.writeOctetString(dn)
            mod.writeSequence { modsList in
                for item in modifications {
                    modsList.writeSequence { modItem in
                        modItem.writeEnumerated(item.operation.rawValue)
                        encodePartialAttribute(item.attribute, into: &modItem)
                    }
                }
            }
        }
    }

    private static func encodeAddRequest(
        dn: String, attributes: [LDAPAttribute], into encoder: inout BEREncoder
    ) {
        encoder.writeSequence(tag: .addRequest) { add in
            add.writeOctetString(dn)
            add.writeSequence { attrList in
                for attr in attributes {
                    encodePartialAttribute(attr, into: &attrList)
                }
            }
        }
    }

    private static func encodeModifyDNRequest(
        dn: String, newRDN: String, deleteOldRDN: Bool, newSuperior: String?,
        into encoder: inout BEREncoder
    ) {
        encoder.writeSequence(tag: .modifyDNRequest) { modDN in
            modDN.writeOctetString(dn)
            modDN.writeOctetString(newRDN)
            modDN.writeBoolean(deleteOldRDN)
            if let newSuperior {
                modDN.writeOctetString(newSuperior, tag: .contextSpecific(0))
            }
        }
    }

    private static func encodeCompareRequest(
        dn: String, attribute: String, value: Data, into encoder: inout BEREncoder
    ) {
        encoder.writeSequence(tag: .compareRequest) { cmp in
            cmp.writeOctetString(dn)
            cmp.writeSequence { ava in
                ava.writeOctetString(attribute)
                ava.writeOctetString(Array(value))
            }
        }
    }

    private static func encodeExtendedRequest(
        oid: String, value: Data?, into encoder: inout BEREncoder
    ) {
        encoder.writeSequence(tag: .extendedRequest) { ext in
            ext.writeOctetString(oid, tag: .contextSpecific(0))
            if let value {
                ext.writeOctetString(Array(value), tag: .contextSpecific(1))
            }
        }
    }

    private static func encodePartialAttribute(
        _ attribute: LDAPAttribute, into encoder: inout BEREncoder
    ) {
        encoder.writeSequence { partial in
            partial.writeOctetString(attribute.type)
            partial.writeSet { vals in
                for value in attribute.values {
                    vals.writeOctetString(Array(value))
                }
            }
        }
    }

    private static func encodeControls(_ controls: [LDAPControl], into encoder: inout BEREncoder) {
        encoder.writeSequence(tag: .contextSpecificConstructed(0)) { ctrlsSeq in
            for ctrl in controls {
                ctrlsSeq.writeSequence { ctrlSeq in
                    ctrlSeq.writeOctetString(ctrl.oid)
                    if ctrl.criticality {
                        ctrlSeq.writeBoolean(true)
                    }
                    if let value = ctrl.value {
                        ctrlSeq.writeOctetString(Array(value))
                    }
                }
            }
        }
    }

    // MARK: - Decoding

    /// Decodes a complete LDAP message from BER bytes.
    ///
    /// Returns the message ID, the decoded operation, and any controls.
    public static func decode(
        _ data: [UInt8]
    ) throws -> (messageID: Int32, operation: LDAPOperation, controls: [LDAPControl]) {
        var outer = BERDecoder(data: data)
        var seq = try outer.readSequence()
        let messageID = try seq.readInt32()
        let opElement = try seq.readElement()
        let operation = try decodeOperation(opElement)

        var controls: [LDAPControl] = []
        if seq.hasMore {
            if let ctrlsElement = try seq.readOptionalElement(tag: .contextSpecificConstructed(0)) {
                controls = try decodeControls(ctrlsElement)
            }
        }

        return (messageID, operation, controls)
    }

    /// Decodes the protocol operation from its BER element.
    static func decodeOperation(_ element: BERElement) throws -> LDAPOperation {
        let tag = element.tag

        switch tag {
        case .bindResponse:
            return try decodeBindResponse(element)
        case .searchResultEntry:
            return try decodeSearchResultEntry(element)
        case .searchResultDone:
            return try .searchResultDone(decodeLDAPResult(element))
        case .searchResultReference:
            return try decodeSearchResultReference(element)
        case .modifyResponse:
            return try .modifyResponse(decodeLDAPResult(element))
        case .addResponse:
            return try .addResponse(decodeLDAPResult(element))
        case .deleteResponse:
            return try .deleteResponse(decodeLDAPResult(element))
        case .modifyDNResponse:
            return try .modifyDNResponse(decodeLDAPResult(element))
        case .compareResponse:
            return try .compareResponse(decodeLDAPResult(element))
        case .extendedResponse:
            return try decodeExtendedResponse(element)
        case .intermediateResponse:
            return try decodeIntermediateResponse(element)
        default:
            throw BERDecodingError.invalidData("Unknown operation tag: \(tag.rawValue)")
        }
    }

    // MARK: - Response Decoding Helpers

    private static func decodeLDAPResult(_ element: BERElement) throws -> LDAPResult {
        var decoder = element.constructedDecoder()
        let code = try decoder.readEnumerated()
        let matchedDN = try decoder.readString()
        let diagnosticMessage = try decoder.readString()

        var referrals: [String] = []
        if decoder.hasMore {
            if let refElement = try decoder.readOptionalElement(
                tag: .contextSpecificConstructed(3)
            ) {
                var refDecoder = refElement.constructedDecoder()
                while refDecoder.hasMore {
                    referrals.append(try refDecoder.readString())
                    guard referrals.count <= maxReferrals else {
                        throw BERDecodingError.invalidData("Too many referrals")
                    }
                }
            }
        }

        guard let resultCode = LDAPResultCode(rawValue: code) else {
            throw BERDecodingError.invalidEnumeratedValue(code)
        }

        return LDAPResult(
            resultCode: resultCode,
            matchedDN: matchedDN,
            diagnosticMessage: diagnosticMessage,
            referrals: referrals
        )
    }

    private static func decodeBindResponse(_ element: BERElement) throws -> LDAPOperation {
        var decoder = element.constructedDecoder()
        let code = try decoder.readEnumerated()
        let matchedDN = try decoder.readString()
        let diagnosticMessage = try decoder.readString()

        var referrals: [String] = []
        var serverSASLCreds: Data?

        while decoder.hasMore {
            let nextTag = try decoder.peekTag()
            if nextTag == .contextSpecificConstructed(3) {
                let refElement = try decoder.readElement()
                var refDecoder = refElement.constructedDecoder()
                while refDecoder.hasMore {
                    referrals.append(try refDecoder.readString())
                    guard referrals.count <= maxReferrals else {
                        throw BERDecodingError.invalidData("Too many referrals")
                    }
                }
            } else if nextTag == .contextSpecific(7) {
                let credsElement = try decoder.readElement()
                serverSASLCreds = Data(credsElement.octetBytes())
            } else {
                try decoder.skipElement()
            }
        }

        guard let resultCode = LDAPResultCode(rawValue: code) else {
            throw BERDecodingError.invalidEnumeratedValue(code)
        }

        let result = LDAPResult(
            resultCode: resultCode,
            matchedDN: matchedDN,
            diagnosticMessage: diagnosticMessage,
            referrals: referrals
        )
        return .bindResponse(result, serverSASLCreds: serverSASLCreds)
    }

    private static func decodeSearchResultEntry(_ element: BERElement) throws -> LDAPOperation {
        var decoder = element.constructedDecoder()
        let dn = try decoder.readString()

        var attrs: [String: [Data]] = [:]
        var attrListDecoder = try decoder.readSequence()
        while attrListDecoder.hasMore {
            var partialAttr = try attrListDecoder.readSequence()
            let attrType = try partialAttr.readString()
            var valuesDecoder = try partialAttr.readSet()
            var values: [Data] = []
            while valuesDecoder.hasMore {
                values.append(Data(try valuesDecoder.readOctetString()))
            }
            attrs[attrType] = values
        }

        return .searchResultEntry(LDAPEntry(dn: dn, attributes: attrs))
    }

    private static func decodeSearchResultReference(
        _ element: BERElement
    ) throws -> LDAPOperation {
        var decoder = element.constructedDecoder()
        var uris: [String] = []
        while decoder.hasMore {
            uris.append(try decoder.readString())
            guard uris.count <= maxReferrals else {
                throw BERDecodingError.invalidData("Too many referrals")
            }
        }
        return .searchResultReference(uris)
    }

    private static func decodeExtendedResponse(_ element: BERElement) throws -> LDAPOperation {
        var decoder = element.constructedDecoder()
        let code = try decoder.readEnumerated()
        let matchedDN = try decoder.readString()
        let diagnosticMessage = try decoder.readString()

        var referrals: [String] = []
        var oid: String?
        var value: Data?

        while decoder.hasMore {
            let nextTag = try decoder.peekTag()
            if nextTag == .contextSpecificConstructed(3) {
                let refElement = try decoder.readElement()
                var refDecoder = refElement.constructedDecoder()
                while refDecoder.hasMore {
                    referrals.append(try refDecoder.readString())
                    guard referrals.count <= maxReferrals else {
                        throw BERDecodingError.invalidData("Too many referrals")
                    }
                }
            } else if nextTag == .contextSpecific(10) {
                let oidElement = try decoder.readElement()
                oid = oidElement.stringValue()
            } else if nextTag == .contextSpecific(11) {
                let valElement = try decoder.readElement()
                value = Data(valElement.octetBytes())
            } else {
                try decoder.skipElement()
            }
        }

        guard let resultCode = LDAPResultCode(rawValue: code) else {
            throw BERDecodingError.invalidEnumeratedValue(code)
        }

        let result = LDAPResult(
            resultCode: resultCode,
            matchedDN: matchedDN,
            diagnosticMessage: diagnosticMessage,
            referrals: referrals
        )
        return .extendedResponse(result, oid: oid, value: value)
    }

    private static func decodeIntermediateResponse(
        _ element: BERElement
    ) throws -> LDAPOperation {
        var decoder = element.constructedDecoder()
        var oid: String?
        var value: Data?

        while decoder.hasMore {
            let nextTag = try decoder.peekTag()
            if nextTag == .contextSpecific(0) {
                let oidElement = try decoder.readElement()
                oid = oidElement.stringValue()
            } else if nextTag == .contextSpecific(1) {
                let valElement = try decoder.readElement()
                value = Data(valElement.octetBytes())
            } else {
                try decoder.skipElement()
            }
        }

        return .intermediateResponse(oid: oid, value: value)
    }

    private static func decodeControls(_ element: BERElement) throws -> [LDAPControl] {
        var decoder = element.constructedDecoder()
        var controls: [LDAPControl] = []
        while decoder.hasMore {
            var ctrlDecoder = try decoder.readSequence()
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

            controls.append(LDAPControl(oid: oid, criticality: criticality, value: value))
            guard controls.count <= maxControls else {
                throw BERDecodingError.invalidData("Too many controls")
            }
        }
        return controls
    }
}
