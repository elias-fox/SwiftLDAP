import Foundation
import Testing
@testable import SwiftLDAP

@Suite("LDAPServerFingerprint Tests")
struct LDAPServerFingerprintTests {

    // MARK: - Helpers

    private func makeEntry(attributes: [String: [String]]) -> LDAPEntry {
        LDAPEntry(
            dn: "",
            attributes: attributes.mapValues { $0.map { Data($0.utf8) } }
        )
    }

    private func fingerprint(attributes: [String: [String]]) -> LDAPServerFingerprint {
        LDAPServerFingerprint(rootDSEEntries: [makeEntry(attributes: attributes)])
    }

    // MARK: - Empty rootDSE

    @Test("Empty rootDSE: rawEntry is nil, serverType is unknown, all arrays empty")
    func emptyRootDSE() {
        let fp = LDAPServerFingerprint(rootDSEEntries: [])
        #expect(fp.rawEntry == nil)
        #expect(fp.serverType == .unknown)
        #expect(fp.vendorName == nil)
        #expect(fp.vendorVersion == nil)
        #expect(fp.namingContexts.isEmpty)
        #expect(fp.supportedExtensions.isEmpty)
        #expect(fp.supportedControls.isEmpty)
        #expect(fp.supportedFeatures.isEmpty)
        #expect(fp.supportedSASLMechanisms.isEmpty)
        #expect(fp.supportedCapabilities.isEmpty)
        #expect(fp.subschemaSubentry == nil)
    }

    // MARK: - OpenLDAP detection

    @Test("OpenLDAP detected via vendorName")
    func openLDAPViaVendorName() {
        let fp = fingerprint(attributes: ["vendorName": ["OpenLDAP"]])
        #expect(fp.serverType == .openLDAP)
    }

    @Test("OpenLDAP detected via vendorName case-insensitive")
    func openLDAPViaVendorNameCaseInsensitive() {
        let fp = fingerprint(attributes: ["vendorName": ["openldap 2.6"]])
        #expect(fp.serverType == .openLDAP)
    }

    @Test("OpenLDAP detected via supportedExtensions OID prefix")
    func openLDAPViaExtensionOID() {
        let fp = fingerprint(attributes: [
            "supportedExtensions": ["1.3.6.1.4.1.4203.1.11.1"],
        ])
        #expect(fp.serverType == .openLDAP)
    }

    @Test("OpenLDAP detected via supportedFeatures OID prefix")
    func openLDAPViaFeaturesOID() {
        let fp = fingerprint(attributes: [
            "supportedFeatures": ["1.3.6.1.4.1.4203.1.5.1"],
        ])
        #expect(fp.serverType == .openLDAP)
    }

    // MARK: - Active Directory detection

    @Test("Active Directory detected via supportedCapabilities AD V4 OID")
    func activeDirectoryViaCapabilities() {
        let fp = fingerprint(attributes: [
            "supportedCapabilities": ["1.2.840.113556.1.4.800"],
        ])
        #expect(fp.serverType == .activeDirectory)
    }

    @Test("Active Directory detected via supportedCapabilities AD V5.1 OID")
    func activeDirectoryViaCapabilitiesV51() {
        let fp = fingerprint(attributes: [
            "supportedCapabilities": ["1.2.840.113556.1.4.1670"],
        ])
        #expect(fp.serverType == .activeDirectory)
    }

    @Test("Sort control OID in supportedControl does not trigger Active Directory detection")
    func sortControlOIDDoesNotTriggerActiveDirectory() {
        // 1.2.840.113556.1.4.473 is RFC 2891 Server Side Sort — OpenLDAP advertises it too
        let fp = fingerprint(attributes: [
            "vendorName": ["OpenLDAP"],
            "supportedControl": ["1.2.840.113556.1.4.473"],
        ])
        #expect(fp.serverType == .openLDAP)
    }

    @Test("Active Directory takes priority over vendorName-based detection")
    func activeDirectoryPriority() {
        // If a server somehow had both an AD capability OID and an OpenLDAP vendorName, AD wins
        let fp = fingerprint(attributes: [
            "vendorName": ["OpenLDAP"],
            "supportedCapabilities": ["1.2.840.113556.1.4.800"],
        ])
        #expect(fp.serverType == .activeDirectory)
    }

    // MARK: - 389-DS detection

    @Test("389-DS detected via vendorName containing '389-ds'")
    func directory389Via389DS() {
        let fp = fingerprint(attributes: ["vendorName": ["389-ds/2.3.1"]])
        #expect(fp.serverType == .directoryServer389)
    }

    @Test("389-DS detected via vendorName containing 'Red Hat'")
    func directory389ViaRedHat() {
        let fp = fingerprint(attributes: ["vendorName": ["Red Hat Directory Server"]])
        #expect(fp.serverType == .directoryServer389)
    }

    @Test("389-DS detected via vendorName containing 'Fedora Directory'")
    func directory389ViaFedora() {
        let fp = fingerprint(attributes: ["vendorName": ["Fedora Directory Server"]])
        #expect(fp.serverType == .directoryServer389)
    }

    // MARK: - ApacheDS detection

    @Test("ApacheDS detected via vendorName containing 'Apache'")
    func apacheDSViaVendorName() {
        let fp = fingerprint(attributes: ["vendorName": ["Apache Directory Server"]])
        #expect(fp.serverType == .apacheDS)
    }

    // MARK: - Unknown fallback

    @Test("Unknown when no detection signals present")
    func unknownFallback() {
        let fp = fingerprint(attributes: [
            "vendorName": ["SomeBespokeDirectory 1.0"],
            "namingContexts": ["dc=example,dc=com"],
        ])
        #expect(fp.serverType == .unknown)
    }

    // MARK: - Attribute parsing

    @Test("namingContexts correctly parsed from multi-value attribute")
    func namingContextsMultiValue() {
        let fp = fingerprint(attributes: [
            "namingContexts": ["dc=example,dc=org", "dc=other,dc=org"],
        ])
        #expect(fp.namingContexts == ["dc=example,dc=org", "dc=other,dc=org"])
    }

    @Test("supportedControls plural fallback merged with singular")
    func supportedControlsPluralFallback() {
        let fp = fingerprint(attributes: [
            "supportedControl": ["1.2.840.113550.4.2"],
            "supportedControls": ["2.16.840.1.113730.3.4.2"],
        ])
        #expect(fp.supportedControls.contains("1.2.840.113550.4.2"))
        #expect(fp.supportedControls.contains("2.16.840.1.113730.3.4.2"))
    }

    @Test("Duplicate OIDs from singular and plural controls are deduplicated")
    func supportedControlsDeduplication() {
        let oid = "1.2.840.113550.4.2"
        let fp = fingerprint(attributes: [
            "supportedControl": [oid],
            "supportedControls": [oid],
        ])
        #expect(fp.supportedControls.filter { $0 == oid }.count == 1)
    }

    @Test("Attribute lookup is case-insensitive")
    func caseInsensitiveAttributeLookup() {
        let fp = fingerprint(attributes: [
            "VendorName": ["OpenLDAP"],
            "NamingContexts": ["dc=example,dc=com"],
        ])
        #expect(fp.vendorName == "OpenLDAP")
        #expect(fp.namingContexts == ["dc=example,dc=com"])
        #expect(fp.serverType == .openLDAP)
    }

    @Test("rawEntry is set when rootDSE is non-empty")
    func rawEntrySet() {
        let entry = makeEntry(attributes: ["vendorName": ["OpenLDAP"]])
        let fp = LDAPServerFingerprint(rootDSEEntries: [entry])
        #expect(fp.rawEntry == entry)
    }

    // MARK: - LDAPServerType description

    @Test("LDAPServerType descriptions")
    func serverTypeDescriptions() {
        #expect(LDAPServerType.openLDAP.description == "OpenLDAP")
        #expect(LDAPServerType.activeDirectory.description == "Active Directory")
        #expect(LDAPServerType.directoryServer389.description == "389 Directory Server")
        #expect(LDAPServerType.apacheDS.description == "ApacheDS")
        #expect(LDAPServerType.unknown.description == "Unknown")
    }
}
