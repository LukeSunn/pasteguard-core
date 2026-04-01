import XCTest
@testable import PasteGuardCore

final class StringDetectionTests: XCTestCase {

    // MARK: - Luhn Validation

    func testLuhnValidVisa() {
        XCTAssertTrue("4532015112830366".luhnValid())
    }

    func testLuhnValidMastercard() {
        XCTAssertTrue("5425233430109903".luhnValid())
    }

    func testLuhnInvalid() {
        XCTAssertFalse("4532015112830367".luhnValid())
    }

    func testLuhnWithSeparators() {
        XCTAssertTrue("4532-0151-1283-0366".luhnValid())
    }

    // MARK: - China ID Validation

    func testChinaIDValid() {
        XCTAssertTrue("110101199003070011".chinaIDValid())
    }

    func testChinaIDInvalid() {
        XCTAssertFalse("110101199003078030".chinaIDValid())
    }

    func testChinaIDWithX() {
        // ID ending with X (valid checksum)
        XCTAssertTrue("11010119900307803X".chinaIDValid())
    }

    // MARK: - IBAN Validation

    func testIBANValidDE() {
        XCTAssertTrue("DE89370400440532013000".ibanValid())
    }

    func testIBANValidGB() {
        XCTAssertTrue("GB29NWBK60161331926819".ibanValid())
    }

    func testIBANInvalid() {
        XCTAssertFalse("DE00000000000000000000".ibanValid())
    }

    // MARK: - Routing Number Validation

    func testRoutingNumberValid() {
        XCTAssertTrue("021000021".routingNumberValid())
    }

    func testRoutingNumberInvalid() {
        XCTAssertFalse("021000020".routingNumberValid())
    }

    // MARK: - Spain DNI Validation

    func testDNIValid() {
        XCTAssertTrue("12345678Z".dniLetterValid())
    }

    func testDNIInvalid() {
        XCTAssertFalse("12345678A".dniLetterValid())
    }

    // MARK: - Partial Mask

    func testPartialMask() {
        XCTAssertEqual("1234567890".partialMask(), "12******90")
    }

    func testPartialMaskShortString() {
        XCTAssertEqual("abc".partialMask(), "***")
    }

    func testPartialMaskCustomKeep() {
        XCTAssertEqual("1234567890".partialMask(keepFirst: 3, keepLast: 3), "123****890")
    }

    // MARK: - Pattern Matching

    func testContainsMatch() {
        XCTAssertTrue("user@example.com".containsMatch(pattern: .emailPattern))
        XCTAssertFalse("no email here".containsMatch(pattern: .emailPattern))
    }

    func testExtractMatches() {
        let text = "Contact us at a@b.com or c@d.com"
        let emails = text.extractMatches(pattern: .emailPattern)
        XCTAssertEqual(emails.count, 2)
    }

    // MARK: - Truncated Preview

    func testTruncatedPreview() {
        let long = String(repeating: "a", count: 200)
        let preview = long.truncatedPreview(maxLength: 50)
        XCTAssertEqual(preview.count, 53) // 50 + "..."
    }

    func testTruncatedPreviewShort() {
        XCTAssertEqual("short".truncatedPreview(), "short")
    }
}
