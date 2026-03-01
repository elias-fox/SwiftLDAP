import Testing
@testable import SwiftLDAP

@Suite("BER Decoder Tests")
struct BERDecoderTests {

    // MARK: - Boolean Decoding

    @Test("Decodes true")
    func decodeBooleanTrue() throws {
        var decoder = BERDecoder(data: [0x01, 0x01, 0xFF])
        let value = try decoder.readBoolean()
        #expect(value == true)
    }

    @Test("Decodes false")
    func decodeBooleanFalse() throws {
        var decoder = BERDecoder(data: [0x01, 0x01, 0x00])
        let value = try decoder.readBoolean()
        #expect(value == false)
    }

    @Test("Non-zero value decodes as true")
    func decodeBooleanNonZero() throws {
        var decoder = BERDecoder(data: [0x01, 0x01, 0x42])
        let value = try decoder.readBoolean()
        #expect(value == true)
    }

    // MARK: - Integer Decoding

    @Test("Decodes zero")
    func decodeZero() throws {
        var decoder = BERDecoder(data: [0x02, 0x01, 0x00])
        let value = try decoder.readInteger()
        #expect(value == 0)
    }

    @Test("Decodes positive integer")
    func decodePositive() throws {
        var decoder = BERDecoder(data: [0x02, 0x01, 0x7F])
        let value = try decoder.readInteger()
        #expect(value == 127)
    }

    @Test("Decodes 128 (two bytes)")
    func decode128() throws {
        var decoder = BERDecoder(data: [0x02, 0x02, 0x00, 0x80])
        let value = try decoder.readInteger()
        #expect(value == 128)
    }

    @Test("Decodes negative integer")
    func decodeNegative() throws {
        var decoder = BERDecoder(data: [0x02, 0x01, 0xFF])
        let value = try decoder.readInteger()
        #expect(value == -1)
    }

    @Test("Decodes -128")
    func decodeNeg128() throws {
        var decoder = BERDecoder(data: [0x02, 0x01, 0x80])
        let value = try decoder.readInteger()
        #expect(value == -128)
    }

    @Test("Decodes 256")
    func decode256() throws {
        var decoder = BERDecoder(data: [0x02, 0x02, 0x01, 0x00])
        let value = try decoder.readInteger()
        #expect(value == 256)
    }

    // MARK: - OCTET STRING Decoding

    @Test("Decodes empty octet string")
    func decodeEmptyOctetString() throws {
        var decoder = BERDecoder(data: [0x04, 0x00])
        let value = try decoder.readString()
        #expect(value == "")
    }

    @Test("Decodes string")
    func decodeString() throws {
        var decoder = BERDecoder(data: [0x04, 0x03, 0x61, 0x62, 0x63])
        let value = try decoder.readString()
        #expect(value == "abc")
    }

    // MARK: - ENUMERATED Decoding

    @Test("Decodes enumerated")
    func decodeEnumerated() throws {
        var decoder = BERDecoder(data: [0x0A, 0x01, 0x02])
        let value = try decoder.readEnumerated()
        #expect(value == 2)
    }

    // MARK: - NULL Decoding

    @Test("Decodes NULL")
    func decodeNull() throws {
        var decoder = BERDecoder(data: [0x05, 0x00])
        try decoder.readNull()
    }

    // MARK: - Sequence Decoding

    @Test("Decodes sequence with children")
    func decodeSequence() throws {
        let data: [UInt8] = [0x30, 0x07, 0x02, 0x01, 0x01, 0x04, 0x02, 0x68, 0x69]
        var decoder = BERDecoder(data: data)
        var seq = try decoder.readSequence()
        let intVal = try seq.readInteger()
        let strVal = try seq.readString()
        #expect(intVal == 1)
        #expect(strVal == "hi")
        #expect(!seq.hasMore)
    }

    // MARK: - Long-Form Length

    @Test("Decodes long-form length")
    func decodeLongFormLength() throws {
        var data: [UInt8] = [0x04, 0x81, 0xC8]
        data.append(contentsOf: [UInt8](repeating: 0x41, count: 200))
        var decoder = BERDecoder(data: data)
        let value = try decoder.readOctetString()
        #expect(value.count == 200)
        #expect(value.allSatisfy { $0 == 0x41 })
    }

    // MARK: - Peek Tag

    @Test("Peeks at next tag without consuming")
    func peekTag() throws {
        let decoder = BERDecoder(data: [0x02, 0x01, 0x05])
        let tag = try decoder.peekTag()
        #expect(tag == .integer)
        #expect(decoder.hasMore)
    }

    // MARK: - Optional Reading

    @Test("Reads optional element when tag matches")
    func readOptionalPresent() throws {
        var decoder = BERDecoder(data: [0x02, 0x01, 0x05])
        let element = try decoder.readOptionalElement(tag: .integer)
        #expect(element != nil)
        #expect(try element?.integerValue() == 5)
    }

    @Test("Returns nil when optional tag does not match")
    func readOptionalAbsent() throws {
        var decoder = BERDecoder(data: [0x04, 0x01, 0x41])
        let element = try decoder.readOptionalElement(tag: .integer)
        #expect(element == nil)
        // Decoder should not have advanced
        #expect(decoder.hasMore)
    }

    // MARK: - Error Cases

    @Test("Throws on unexpected end of data")
    func unexpectedEnd() {
        var decoder = BERDecoder(data: [])
        #expect(throws: BERDecodingError.self) {
            try decoder.readElement()
        }
    }

    @Test("Throws on wrong tag")
    func wrongTag() {
        var decoder = BERDecoder(data: [0x04, 0x01, 0x41])
        #expect(throws: BERDecodingError.self) {
            try decoder.readElement(expectedTag: .integer)
        }
    }

    @Test("Throws on truncated length")
    func truncatedLength() {
        var decoder = BERDecoder(data: [0x02, 0x82])
        #expect(throws: BERDecodingError.self) {
            try decoder.readElement()
        }
    }

    @Test("Throws on content exceeding data")
    func contentExceedsData() {
        var decoder = BERDecoder(data: [0x02, 0x05, 0x01])
        #expect(throws: BERDecodingError.self) {
            try decoder.readElement()
        }
    }

    @Test("Throws on INTEGER wider than platform Int")
    func decodeOversizedInteger() {
        // 9 content bytes — wider than Int on any 64-bit platform.
        var decoder = BERDecoder(data: [0x02, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        #expect(throws: BERDecodingError.self) {
            try decoder.readInteger()
        }
    }

    // MARK: - Round-Trip Tests

    @Test("Round-trips integer encoding/decoding")
    func roundTripInteger() throws {
        for value in [-1000, -128, -1, 0, 1, 127, 128, 255, 256, 65535, 100000] {
            var encoder = BEREncoder()
            encoder.writeInteger(value)
            let bytes = encoder.finish()
            var decoder = BERDecoder(data: bytes)
            let decoded = try decoder.readInteger()
            #expect(decoded == value, "Round-trip failed for \(value)")
        }
    }

    @Test("Round-trips string encoding/decoding")
    func roundTripString() throws {
        for str in ["", "hello", "café", "日本語", String(repeating: "x", count: 300)] {
            var encoder = BEREncoder()
            encoder.writeOctetString(str)
            let bytes = encoder.finish()
            var decoder = BERDecoder(data: bytes)
            let decoded = try decoder.readString()
            #expect(decoded == str, "Round-trip failed for \"\(str)\"")
        }
    }

    @Test("Round-trips nested sequence")
    func roundTripNestedSequence() throws {
        var encoder = BEREncoder()
        encoder.writeSequence { outer in
            outer.writeInteger(42)
            outer.writeSequence { inner in
                inner.writeOctetString("nested")
                inner.writeBoolean(true)
            }
            outer.writeOctetString("end")
        }
        let bytes = encoder.finish()

        var decoder = BERDecoder(data: bytes)
        var outer = try decoder.readSequence()
        let intVal = try outer.readInteger()
        #expect(intVal == 42)

        var inner = try outer.readSequence()
        let nestedStr = try inner.readString()
        #expect(nestedStr == "nested")
        let boolVal = try inner.readBoolean()
        #expect(boolVal == true)
        #expect(!inner.hasMore)

        let endStr = try outer.readString()
        #expect(endStr == "end")
        #expect(!outer.hasMore)
    }
}
