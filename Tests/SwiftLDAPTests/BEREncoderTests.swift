import Testing
@testable import SwiftLDAP

@Suite("BER Encoder Tests")
struct BEREncoderTests {

    // MARK: - Boolean Encoding

    @Test("Encodes true as 0xFF")
    func encodeBooleanTrue() {
        var encoder = BEREncoder()
        encoder.writeBoolean(true)
        let bytes = encoder.finish()
        #expect(bytes == [0x01, 0x01, 0xFF])
    }

    @Test("Encodes false as 0x00")
    func encodeBooleanFalse() {
        var encoder = BEREncoder()
        encoder.writeBoolean(false)
        let bytes = encoder.finish()
        #expect(bytes == [0x01, 0x01, 0x00])
    }

    // MARK: - Integer Encoding

    @Test("Encodes zero")
    func encodeZero() {
        var encoder = BEREncoder()
        encoder.writeInteger(0)
        let bytes = encoder.finish()
        #expect(bytes == [0x02, 0x01, 0x00])
    }

    @Test("Encodes small positive integer")
    func encodeSmallPositive() {
        var encoder = BEREncoder()
        encoder.writeInteger(127)
        let bytes = encoder.finish()
        #expect(bytes == [0x02, 0x01, 0x7F])
    }

    @Test("Encodes 128 (requires 2 bytes due to sign bit)")
    func encode128() {
        var encoder = BEREncoder()
        encoder.writeInteger(128)
        let bytes = encoder.finish()
        // 128 = 0x80, but that would look negative in BER, so it becomes 0x00 0x80
        #expect(bytes == [0x02, 0x02, 0x00, 0x80])
    }

    @Test("Encodes negative integer")
    func encodeNegative() {
        var encoder = BEREncoder()
        encoder.writeInteger(-1)
        let bytes = encoder.finish()
        #expect(bytes == [0x02, 0x01, 0xFF])
    }

    @Test("Encodes -128")
    func encodeNeg128() {
        var encoder = BEREncoder()
        encoder.writeInteger(-128)
        let bytes = encoder.finish()
        #expect(bytes == [0x02, 0x01, 0x80])
    }

    @Test("Encodes larger integer")
    func encodeLargerInteger() {
        var encoder = BEREncoder()
        encoder.writeInteger(256)
        let bytes = encoder.finish()
        #expect(bytes == [0x02, 0x02, 0x01, 0x00])
    }

    // MARK: - OCTET STRING Encoding

    @Test("Encodes empty octet string")
    func encodeEmptyOctetString() {
        var encoder = BEREncoder()
        encoder.writeOctetString("")
        let bytes = encoder.finish()
        #expect(bytes == [0x04, 0x00])
    }

    @Test("Encodes string as octet string")
    func encodeStringOctetString() {
        var encoder = BEREncoder()
        encoder.writeOctetString("abc")
        let bytes = encoder.finish()
        #expect(bytes == [0x04, 0x03, 0x61, 0x62, 0x63])
    }

    // MARK: - NULL Encoding

    @Test("Encodes NULL")
    func encodeNull() {
        var encoder = BEREncoder()
        encoder.writeNull()
        let bytes = encoder.finish()
        #expect(bytes == [0x05, 0x00])
    }

    // MARK: - ENUMERATED Encoding

    @Test("Encodes enumerated value")
    func encodeEnumerated() {
        var encoder = BEREncoder()
        encoder.writeEnumerated(2)
        let bytes = encoder.finish()
        #expect(bytes == [0x0A, 0x01, 0x02])
    }

    // MARK: - Sequence Encoding

    @Test("Encodes empty sequence")
    func encodeEmptySequence() {
        var encoder = BEREncoder()
        encoder.writeSequence { _ in }
        let bytes = encoder.finish()
        #expect(bytes == [0x30, 0x00])
    }

    @Test("Encodes sequence with children")
    func encodeSequenceWithChildren() {
        var encoder = BEREncoder()
        encoder.writeSequence { seq in
            seq.writeInteger(1)
            seq.writeOctetString("hi")
        }
        let bytes = encoder.finish()
        // SEQUENCE { INTEGER 1, OCTET STRING "hi" }
        // 0x30, length, 0x02 0x01 0x01, 0x04 0x02 0x68 0x69
        let expected: [UInt8] = [0x30, 0x07, 0x02, 0x01, 0x01, 0x04, 0x02, 0x68, 0x69]
        #expect(bytes == expected)
    }

    // MARK: - Long-Form Length

    @Test("Encodes long-form length for large content")
    func encodeLongFormLength() {
        var encoder = BEREncoder()
        let data = [UInt8](repeating: 0x41, count: 200)
        encoder.writeOctetString(data)
        let bytes = encoder.finish()
        // Tag 0x04, length 0x81 0xC8 (long form: 1 byte for 200), then 200 bytes of 0x41
        #expect(bytes[0] == 0x04)
        #expect(bytes[1] == 0x81) // 0x80 | 1 (1 length byte follows)
        #expect(bytes[2] == 0xC8) // 200
        #expect(bytes.count == 3 + 200)
    }

    // MARK: - Custom Tags

    @Test("Encodes with application tag")
    func encodeApplicationTag() {
        var encoder = BEREncoder()
        encoder.writeSequence(tag: .bindRequest) { bind in
            bind.writeInteger(3)
        }
        let bytes = encoder.finish()
        // APPLICATION 0 CONSTRUCTED
        #expect(bytes[0] == 0x60) // 0x40 | 0x20 | 0x00
    }

    @Test("Encodes with context-specific tag")
    func encodeContextSpecificTag() {
        var encoder = BEREncoder()
        encoder.writeOctetString("password", tag: .contextSpecific(0))
        let bytes = encoder.finish()
        #expect(bytes[0] == 0x80) // context-specific [0] primitive
    }
}
