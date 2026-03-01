/// LDAP result codes as defined in RFC 4511 §4.1.9.
///
/// These codes are returned by the server in all result messages
/// (BindResponse, SearchResultDone, ModifyResponse, etc.).
public enum LDAPResultCode: Int, Sendable, Equatable, Hashable, CustomStringConvertible {
    case success = 0
    case operationsError = 1
    case protocolError = 2
    case timeLimitExceeded = 3
    case sizeLimitExceeded = 4
    case compareFalse = 5
    case compareTrue = 6
    case authMethodNotSupported = 7
    case strongerAuthRequired = 8
    case referral = 10
    case adminLimitExceeded = 11
    case unavailableCriticalExtension = 12
    case confidentialityRequired = 13
    case saslBindInProgress = 14
    case noSuchAttribute = 16
    case undefinedAttributeType = 17
    case inappropriateMatching = 18
    case constraintViolation = 19
    case attributeOrValueExists = 20
    case invalidAttributeSyntax = 21
    case noSuchObject = 32
    case aliasProblem = 33
    case invalidDNSyntax = 34
    case aliasDereferencingProblem = 36
    case inappropriateAuthentication = 48
    case invalidCredentials = 49
    case insufficientAccessRights = 50
    case busy = 51
    case unavailable = 52
    case unwillingToPerform = 53
    case loopDetect = 54
    case namingViolation = 64
    case objectClassViolation = 65
    case notAllowedOnNonLeaf = 66
    case notAllowedOnRDN = 67
    case entryAlreadyExists = 68
    case objectClassModsProhibited = 69
    case affectsMultipleDSAs = 71
    case other = 80

    public var description: String {
        switch self {
        case .success: return "success"
        case .operationsError: return "operationsError"
        case .protocolError: return "protocolError"
        case .timeLimitExceeded: return "timeLimitExceeded"
        case .sizeLimitExceeded: return "sizeLimitExceeded"
        case .compareFalse: return "compareFalse"
        case .compareTrue: return "compareTrue"
        case .authMethodNotSupported: return "authMethodNotSupported"
        case .strongerAuthRequired: return "strongerAuthRequired"
        case .referral: return "referral"
        case .adminLimitExceeded: return "adminLimitExceeded"
        case .unavailableCriticalExtension: return "unavailableCriticalExtension"
        case .confidentialityRequired: return "confidentialityRequired"
        case .saslBindInProgress: return "saslBindInProgress"
        case .noSuchAttribute: return "noSuchAttribute"
        case .undefinedAttributeType: return "undefinedAttributeType"
        case .inappropriateMatching: return "inappropriateMatching"
        case .constraintViolation: return "constraintViolation"
        case .attributeOrValueExists: return "attributeOrValueExists"
        case .invalidAttributeSyntax: return "invalidAttributeSyntax"
        case .noSuchObject: return "noSuchObject"
        case .aliasProblem: return "aliasProblem"
        case .invalidDNSyntax: return "invalidDNSyntax"
        case .aliasDereferencingProblem: return "aliasDereferencingProblem"
        case .inappropriateAuthentication: return "inappropriateAuthentication"
        case .invalidCredentials: return "invalidCredentials"
        case .insufficientAccessRights: return "insufficientAccessRights"
        case .busy: return "busy"
        case .unavailable: return "unavailable"
        case .unwillingToPerform: return "unwillingToPerform"
        case .loopDetect: return "loopDetect"
        case .namingViolation: return "namingViolation"
        case .objectClassViolation: return "objectClassViolation"
        case .notAllowedOnNonLeaf: return "notAllowedOnNonLeaf"
        case .notAllowedOnRDN: return "notAllowedOnRDN"
        case .entryAlreadyExists: return "entryAlreadyExists"
        case .objectClassModsProhibited: return "objectClassModsProhibited"
        case .affectsMultipleDSAs: return "affectsMultipleDSAs"
        case .other: return "other"
        }
    }
}
