import Foundation

/// Errors that can occur during BER decoding.
public enum BERDecodingError: Error, Sendable {
    /// The data ended before the expected number of bytes could be read.
    case unexpectedEndOfData
    /// A tag byte did not match the expected tag.
    case unexpectedTag(expected: ASN1Tag, actual: ASN1Tag)
    /// An indefinite-length encoding was encountered (not permitted in LDAP).
    case indefiniteLengthNotSupported
    /// The encoded length exceeds the remaining data.
    case lengthExceedsData(length: Int, available: Int)
    /// An integer encoding was invalid (e.g., empty content for INTEGER).
    case invalidIntegerEncoding
    /// An ENUMERATED value was not recognized.
    case invalidEnumeratedValue(Int)
    /// A BOOLEAN encoding was invalid.
    case invalidBooleanEncoding
    /// Generic decode failure with a descriptive message.
    case invalidData(String)
}

/// A decoded BER TLV element.
public struct BERElement: Sendable {
    /// The tag of this element.
    public let tag: ASN1Tag
    /// The raw content bytes (excluding tag and length).
    public let content: ArraySlice<UInt8>

    /// Interprets the content as a BOOLEAN.
    public func booleanValue() throws -> Bool {
        guard content.count == 1 else {
            throw BERDecodingError.invalidBooleanEncoding
        }
        return content[content.startIndex] != 0x00
    }

    /// Interprets the content as an INTEGER, returning an `Int`.
    public func integerValue() throws -> Int {
        guard !content.isEmpty else {
            throw BERDecodingError.invalidIntegerEncoding
        }
        var result: Int = 0
        let isNegative = content[content.startIndex] & 0x80 != 0
        for byte in content {
            result = (result << 8) | Int(byte)
        }
        // Sign-extend if the high bit is set.
        if isNegative {
            let shift = (MemoryLayout<Int>.size - content.count) * 8
            result = (result << shift) >> shift
        }
        return result
    }

    /// Interprets the content as an Int32.
    public func int32Value() throws -> Int32 {
        Int32(try integerValue())
    }

    /// Interprets the content as an ENUMERATED value.
    public func enumeratedValue() throws -> Int {
        try integerValue()
    }

    /// Interprets the content as raw bytes.
    public func octetBytes() -> [UInt8] {
        Array(content)
    }

    /// Interprets the content as a UTF-8 string.
    public func stringValue() -> String {
        String(decoding: content, as: UTF8.self)
    }

    /// Creates a sub-decoder for reading constructed (nested) content.
    public func constructedDecoder() -> BERDecoder {
        BERDecoder(data: content)
    }
}

/// Reads BER-encoded elements from a byte buffer.
///
/// This decoder processes Tag-Length-Value triplets sequentially.
/// It only supports definite-length encodings, as required by LDAP (RFC 4511 §5.1).
public struct BERDecoder: Sendable {
    private let data: ArraySlice<UInt8>
    private var offset: Int

    /// Creates a decoder that reads from the given bytes.
    public init(data: some Collection<UInt8>) {
        if let slice = data as? ArraySlice<UInt8> {
            self.data = slice
        } else {
            self.data = ArraySlice(data)
        }
        self.offset = self.data.startIndex
    }

    /// Whether there is more data to read.
    public var hasMore: Bool {
        offset < data.endIndex
    }

    /// The number of remaining bytes.
    public var remainingCount: Int {
        data.endIndex - offset
    }

    // MARK: - Reading Elements

    /// Reads the next TLV element from the buffer.
    public mutating func readElement() throws -> BERElement {
        let tag = try readTagByte()
        let length = try readLength()
        let content = try readBytes(length)
        return BERElement(tag: tag, content: content)
    }

    /// Reads the next element and verifies its tag matches the expected tag.
    public mutating func readElement(expectedTag: ASN1Tag) throws -> BERElement {
        let element = try readElement()
        guard element.tag == expectedTag else {
            throw BERDecodingError.unexpectedTag(expected: expectedTag, actual: element.tag)
        }
        return element
    }

    /// Peeks at the next tag without advancing the decoder.
    public func peekTag() throws -> ASN1Tag {
        guard offset < data.endIndex else {
            throw BERDecodingError.unexpectedEndOfData
        }
        return ASN1Tag(rawValue: data[offset])
    }

    // MARK: - Typed Readers

    /// Reads a BOOLEAN.
    public mutating func readBoolean(tag: ASN1Tag = .boolean) throws -> Bool {
        try readElement(expectedTag: tag).booleanValue()
    }

    /// Reads an INTEGER as `Int`.
    public mutating func readInteger(tag: ASN1Tag = .integer) throws -> Int {
        try readElement(expectedTag: tag).integerValue()
    }

    /// Reads an INTEGER as `Int32`.
    public mutating func readInt32(tag: ASN1Tag = .integer) throws -> Int32 {
        try readElement(expectedTag: tag).int32Value()
    }

    /// Reads an ENUMERATED value.
    public mutating func readEnumerated(tag: ASN1Tag = .enumerated) throws -> Int {
        try readElement(expectedTag: tag).enumeratedValue()
    }

    /// Reads an OCTET STRING as raw bytes.
    public mutating func readOctetString(tag: ASN1Tag = .octetString) throws -> [UInt8] {
        try readElement(expectedTag: tag).octetBytes()
    }

    /// Reads an OCTET STRING as a UTF-8 string.
    public mutating func readString(tag: ASN1Tag = .octetString) throws -> String {
        try readElement(expectedTag: tag).stringValue()
    }

    /// Reads a SEQUENCE, returning a sub-decoder for its content.
    public mutating func readSequence(tag: ASN1Tag = .sequence) throws -> BERDecoder {
        try readElement(expectedTag: tag).constructedDecoder()
    }

    /// Reads a SET, returning a sub-decoder for its content.
    public mutating func readSet(tag: ASN1Tag = .set) throws -> BERDecoder {
        try readElement(expectedTag: tag).constructedDecoder()
    }

    /// Reads a NULL element.
    public mutating func readNull(tag: ASN1Tag = .null) throws {
        let element = try readElement(expectedTag: tag)
        guard element.content.isEmpty else {
            throw BERDecodingError.invalidData("NULL element must have zero-length content")
        }
    }

    /// Skips the next element without decoding its content.
    public mutating func skipElement() throws {
        _ = try readElement()
    }

    // MARK: - Optional Reading

    /// If the next element has the given tag, reads and returns it; otherwise returns nil.
    public mutating func readOptionalElement(tag: ASN1Tag) throws -> BERElement? {
        guard hasMore else { return nil }
        let nextTag = try peekTag()
        guard nextTag == tag else { return nil }
        return try readElement()
    }

    // MARK: - Low-Level

    /// Reads a single tag byte.
    private mutating func readTagByte() throws -> ASN1Tag {
        guard offset < data.endIndex else {
            throw BERDecodingError.unexpectedEndOfData
        }
        let tag = ASN1Tag(rawValue: data[offset])
        offset += 1
        return tag
    }

    /// Reads a BER definite-length field.
    private mutating func readLength() throws -> Int {
        guard offset < data.endIndex else {
            throw BERDecodingError.unexpectedEndOfData
        }
        let first = data[offset]
        offset += 1

        if first & 0x80 == 0 {
            // Short form: length is in the low 7 bits.
            return Int(first)
        }

        let numBytes = Int(first & 0x7F)
        guard numBytes > 0 else {
            throw BERDecodingError.indefiniteLengthNotSupported
        }
        guard numBytes <= 4 else {
            throw BERDecodingError.invalidData("BER length field too large (\(numBytes) bytes)")
        }
        guard offset + numBytes <= data.endIndex else {
            throw BERDecodingError.unexpectedEndOfData
        }

        var length = 0
        for i in 0..<numBytes {
            length = (length << 8) | Int(data[offset + i])
        }
        offset += numBytes

        return length
    }

    /// Reads the specified number of bytes as a slice.
    private mutating func readBytes(_ count: Int) throws -> ArraySlice<UInt8> {
        guard offset + count <= data.endIndex else {
            throw BERDecodingError.lengthExceedsData(
                length: count,
                available: data.endIndex - offset
            )
        }
        let slice = data[offset..<(offset + count)]
        offset += count
        return slice
    }
}

// MARK: - Message-Level Helpers

/// Decodes the outer LDAP message envelope (SEQUENCE { messageID, protocolOp, [controls] }).
///
/// Returns the message ID and a decoder positioned at the protocol operation element.
public func decodeLDAPMessageEnvelope(
    from data: [UInt8]
) throws -> (messageID: Int32, decoder: BERDecoder) {
    var outer = BERDecoder(data: data)
    var seq = try outer.readSequence()
    let messageID = try seq.readInt32()
    return (messageID, seq)
}
