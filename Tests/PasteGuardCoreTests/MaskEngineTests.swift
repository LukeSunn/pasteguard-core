import XCTest
@testable import PasteGuardCore

final class MaskEngineTests: XCTestCase {

    let maskEngine = MaskEngine()
    let ruleEngine = RuleEngine()

    func testPartialMask() {
        let content = "Card: 4532015112830366"
        let matches = ruleEngine.scan(content: content)
        let masked = maskEngine.mask(content: content, matches: matches, style: .partial)
        XCTAssertFalse(masked.contains("4532015112830366"), "Original should be masked")
        XCTAssertTrue(masked.contains("*"), "Should contain mask characters")
    }

    func testFullMask() {
        let content = "SSN: 123-45-6789"
        let matches = ruleEngine.scan(content: content)
        let masked = maskEngine.mask(content: content, matches: matches, style: .full)
        XCTAssertFalse(masked.contains("123-45-6789"), "Original should be masked")
    }

    func testCustomMask() {
        let content = "Email: user@example.com"
        let matches = ruleEngine.scan(content: content)
        let masked = maskEngine.mask(content: content, matches: matches, style: .custom("[REDACTED]"))
        XCTAssertTrue(masked.contains("[REDACTED]"), "Should use custom replacement")
    }

    func testEmptyMatchesReturnsOriginal() {
        let content = "Nothing sensitive here"
        let masked = maskEngine.mask(content: content, matches: [], style: .partial)
        XCTAssertEqual(masked, content, "No matches should return original")
    }

    func testMaskForPreview() {
        let content = "Card 4532015112830366 and SSN 123-45-6789"
        let preview = maskEngine.maskForPreview(content)
        XCTAssertFalse(preview.contains("4532015112830366"), "Card should be masked in preview")
    }
}
