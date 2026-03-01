import Foundation

/// Encodes values into BER (Basic Encoding Rules) format as defined in ITU-T X.690.
///
/// BER is a Tag-Length-Value (TLV) encoding used by LDAP for all protocol messages.
/// This encoder produces definite-length encodings (as required by LDAP / RFC 4511 §5.1).
public struct BEREncoder: Sendable {

    /// The accumulated encoded bytes.
    private var buffer: [UInt8] = []

    public init() {}

    /// Returns the encoded bytes and resets the encoder.
    public mutating func finish() -> [UInt8] {
        let result = buffer
        buffer = []
        return result
    }

    /// Returns the current encoded bytes without resetting.
    public var bytes: [UInt8] { buffer }

    // MARK: - Primitive Encoders

    /// Encodes a BOOLEAN value.
    public mutating func writeBoolean(_ value: Bool, tag: ASN1Tag = .boolean) {
        writeTag(tag)
        writeLength(1)
        buffer.append(value ? 0xFF : 0x00)
    }

    /// Encodes an INTEGER value.
    public mutating func writeInteger(_ value: Int, tag: ASN1Tag = .integer) {
        let encoded = encodeIntegerBytes(value)
        writeTag(tag)
        writeLength(encoded.count)
        buffer.append(contentsOf: encoded)
    }

    /// Encodes an INTEGER value from an Int32.
    public mutating func writeInteger(_ value: Int32, tag: ASN1Tag = .integer) {
        writeInteger(Int(value), tag: tag)
    }

    /// Encodes an ENUMERATED value.
    public mutating func writeEnumerated(_ value: Int, tag: ASN1Tag = .enumerated) {
        writeInteger(value, tag: tag)
    }

    /// Encodes an OCTET STRING from raw bytes.
    public mutating func writeOctetString(_ data: [UInt8], tag: ASN1Tag = .octetString) {
        writeTag(tag)
        writeLength(data.count)
        buffer.append(contentsOf: data)
    }

    /// Encodes an OCTET STRING from a Swift string (UTF-8).
    public mutating func writeOctetString(_ string: String, tag: ASN1Tag = .octetString) {
        writeOctetString(Array(string.utf8), tag: tag)
    }

    /// Encodes a NULL value.
    public mutating func writeNull(tag: ASN1Tag = .null) {
        writeTag(tag)
        writeLength(0)
    }

    // MARK: - Constructed Encoders

    /// Encodes a SEQUENCE: the closure writes child elements into a sub-encoder,
    /// whose output is then wrapped with the SEQUENCE tag and length.
    public mutating func writeSequence(
        tag: ASN1Tag = .sequence,
        _ body: (inout BEREncoder) -> Void
    ) {
        var sub = BEREncoder()
        body(&sub)
        let content = sub.finish()
        writeTag(tag)
        writeLength(content.count)
        buffer.append(contentsOf: content)
    }

    /// Encodes a SET.
    public mutating func writeSet(
        tag: ASN1Tag = .set,
        _ body: (inout BEREncoder) -> Void
    ) {
        writeSequence(tag: tag, body)
    }

    /// Writes pre-encoded raw bytes directly into the buffer.
    public mutating func writeRawBytes(_ bytes: [UInt8]) {
        buffer.append(contentsOf: bytes)
    }

    // MARK: - Low-Level

    /// Writes a tag byte.
    public mutating func writeTag(_ tag: ASN1Tag) {
        buffer.append(tag.rawValue)
    }

    /// Writes a BER definite-length encoding.
    ///
    /// - Short form (length 0–127): single byte.
    /// - Long form (length ≥ 128): first byte is 0x80 | number-of-length-bytes,
    ///   followed by the length in big-endian bytes.
    public mutating func writeLength(_ length: Int) {
        precondition(length >= 0)
        if length < 0x80 {
            buffer.append(UInt8(length))
        } else {
            let lengthBytes = encodeLengthBytes(length)
            buffer.append(0x80 | UInt8(lengthBytes.count))
            buffer.append(contentsOf: lengthBytes)
        }
    }

    // MARK: - Private Helpers

    /// Encodes an integer as the minimum number of two's-complement bytes.
    private func encodeIntegerBytes(_ value: Int) -> [UInt8] {
        if value == 0 { return [0x00] }

        var result: [UInt8] = []
        var v = value
        // Extract bytes in little-endian order, then reverse.
        while true {
            result.append(UInt8(truncatingIfNeeded: v & 0xFF))
            v >>= 8
            // Stop when all remaining bits are the sign extension of the current MSB.
            if (v == 0 && result.last! & 0x80 == 0) ||
               (v == -1 && result.last! & 0x80 != 0) {
                break
            }
        }
        return result.reversed()
    }

    /// Encodes a length value as big-endian bytes (for long-form lengths).
    private func encodeLengthBytes(_ length: Int) -> [UInt8] {
        var result: [UInt8] = []
        var v = length
        while v > 0 {
            result.append(UInt8(v & 0xFF))
            v >>= 8
        }
        return result.reversed()
    }
}

// MARK: - Convenience Free Functions

/// Encodes an LDAP message envelope (SEQUENCE { messageID, protocolOp, [controls] }).
public func encodeLDAPMessage(
    messageID: Int32,
    body: (inout BEREncoder) -> Void
) -> [UInt8] {
    var encoder = BEREncoder()
    encoder.writeSequence { seq in
        seq.writeInteger(messageID)
        body(&seq)
    }
    return encoder.finish()
}
