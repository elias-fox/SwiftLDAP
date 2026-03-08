import Foundation
import Testing
@testable import SwiftLDAP

@Suite("LDAP Model Tests")
struct LDAPModelTests {

    // MARK: - LDAPEntry

    @Test("Entry string values retrieval")
    func entryStringValues() {
        let entry = LDAPEntry(
            dn: "cn=test,dc=example,dc=com",
            attributes: [
                "cn": [Data("test".utf8)],
                "mail": [Data("a@example.com".utf8), Data("b@example.com".utf8)],
                "objectClass": [Data("top".utf8), Data("person".utf8)],
            ]
        )

        #expect(entry.stringValues(for: "cn") == ["test"])
        #expect(entry.stringValues(for: "mail") == ["a@example.com", "b@example.com"])
        #expect(entry.firstValue(for: "cn") == "test")
        #expect(entry.stringValues(for: "nonexistent") == [])
        #expect(entry.firstValue(for: "nonexistent") == nil)
    }

    // MARK: - LDAPAttribute

    @Test("Attribute from string values")
    func attributeStringInit() {
        let attr = LDAPAttribute(type: "cn", stringValues: ["John", "Johnny"])
        #expect(attr.type == "cn")
        #expect(attr.values.count == 2)
        #expect(attr.values[0] == Data("John".utf8))
        #expect(attr.values[1] == Data("Johnny".utf8))
    }

    // MARK: - LDAPResult

    @Test("LDAPResult initialization")
    func resultInit() {
        let result = LDAPResult(
            resultCode: .success,
            matchedDN: "dc=example",
            diagnosticMessage: "OK"
        )
        #expect(result.resultCode == .success)
        #expect(result.matchedDN == "dc=example")
        #expect(result.diagnosticMessage == "OK")
        #expect(result.referrals.isEmpty)
    }

    // MARK: - LDAPResultCode

    @Test("Result code descriptions")
    func resultCodeDescriptions() {
        #expect(String(describing: LDAPResultCode.success) == "success")
        #expect(String(describing: LDAPResultCode.invalidCredentials) == "invalidCredentials")
        #expect(String(describing: LDAPResultCode.noSuchObject) == "noSuchObject")
    }

    @Test("Result code raw values match RFC 4511")
    func resultCodeRawValues() {
        #expect(LDAPResultCode.success.rawValue == 0)
        #expect(LDAPResultCode.operationsError.rawValue == 1)
        #expect(LDAPResultCode.protocolError.rawValue == 2)
        #expect(LDAPResultCode.sizeLimitExceeded.rawValue == 4)
        #expect(LDAPResultCode.compareFalse.rawValue == 5)
        #expect(LDAPResultCode.compareTrue.rawValue == 6)
        #expect(LDAPResultCode.saslBindInProgress.rawValue == 14)
        #expect(LDAPResultCode.noSuchObject.rawValue == 32)
        #expect(LDAPResultCode.invalidCredentials.rawValue == 49)
        #expect(LDAPResultCode.entryAlreadyExists.rawValue == 68)
        #expect(LDAPResultCode.other.rawValue == 80)
    }

    // MARK: - LDAPControl

    @Test("Control initialization")
    func controlInit() {
        let ctrl = LDAPControl(oid: "1.2.3.4.5", criticality: true, value: Data([0x01, 0x02]))
        #expect(ctrl.oid == "1.2.3.4.5")
        #expect(ctrl.criticality == true)
        #expect(ctrl.value == Data([0x01, 0x02]))
    }

    @Test("Control with defaults")
    func controlDefaults() {
        let ctrl = LDAPControl(oid: "1.2.3")
        #expect(ctrl.criticality == false)
        #expect(ctrl.value == nil)
    }

    // MARK: - SearchParameters

    @Test("Search parameters with defaults")
    func searchParamsDefaults() {
        let params = SearchParameters(
            baseDN: "dc=example,dc=com",
            filter: .present(attribute: "objectClass")
        )
        #expect(params.scope == .wholeSubtree)
        #expect(params.derefAliases == .never)
        #expect(params.sizeLimit == 0)
        #expect(params.timeLimit == 0)
        #expect(params.typesOnly == false)
        #expect(params.attributes.isEmpty)
    }

    // MARK: - ModifyItem

    @Test("Modify item creation")
    func modifyItem() {
        let item = ModifyItem(
            operation: .replace,
            attribute: LDAPAttribute(type: "mail", stringValues: ["new@example.com"])
        )
        #expect(item.operation == .replace)
        #expect(item.attribute.type == "mail")
    }

    // MARK: - ASN1Tag

    @Test("ASN1 tag components")
    func tagComponents() {
        let tag = ASN1Tag.bindRequest
        #expect(tag.tagClass == .application)
        #expect(tag.isConstructed == true)
        #expect(tag.tagNumber == 0)
    }

    @Test("Context-specific tag helpers")
    func contextSpecificTags() {
        let primitive = ASN1Tag.contextSpecific(3)
        #expect(primitive.tagClass == .contextSpecific)
        #expect(primitive.isConstructed == false)
        #expect(primitive.tagNumber == 3)
        #expect(primitive.rawValue == 0x83)

        let constructed = ASN1Tag.contextSpecificConstructed(5)
        #expect(constructed.tagClass == .contextSpecific)
        #expect(constructed.isConstructed == true)
        #expect(constructed.tagNumber == 5)
        #expect(constructed.rawValue == 0xA5)
    }

    // MARK: - LDAPConnectionConfig

    @Test("Connection config defaults to StartTLS on port 389")
    func connectionConfigDefaults() {
        let config = LDAPConnectionConfig(host: "ldap.example.com")
        #expect(config.host == "ldap.example.com")
        #expect(config.port == 389)
        #expect(config.security == .startTLS)
    }

    @Test("Connection config with LDAPS defaults to port 636")
    func connectionConfigLDAPS() {
        let config = LDAPConnectionConfig(host: "ldap.example.com", security: .ldaps)
        #expect(config.port == 636)
        #expect(config.security == .ldaps)
    }

    @Test("Connection config with StartTLS defaults to port 389")
    func connectionConfigStartTLS() {
        let config = LDAPConnectionConfig(host: "ldap.example.com", security: .startTLS)
        #expect(config.port == 389)
        #expect(config.security == .startTLS)
    }

    @Test("Connection config custom port overrides default")
    func connectionConfigCustomPort() {
        let config = LDAPConnectionConfig(host: "ldap.example.com", port: 1389, security: .ldaps)
        #expect(config.port == 1389)
        #expect(config.security == .ldaps)
    }
}
