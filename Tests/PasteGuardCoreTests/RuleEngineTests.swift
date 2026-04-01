import XCTest
@testable import PasteGuardCore

final class RuleEngineTests: XCTestCase {

    let engine = RuleEngine()

    // MARK: - Credit Card

    func testCreditCardVisa() {
        let matches = engine.scan(content: "Card: 4532015112830366")
        let ccMatches = matches.filter { $0.ruleId == "cc" }
        XCTAssertFalse(ccMatches.isEmpty, "Should detect Visa card")
        XCTAssertEqual(ccMatches.first?.riskLevel, .critical)
    }

    func testCreditCardMastercard() {
        let matches = engine.scan(content: "Pay with 5425233430109903")
        let ccMatches = matches.filter { $0.ruleId == "cc" }
        XCTAssertFalse(ccMatches.isEmpty, "Should detect Mastercard")
    }

    func testCreditCardAmex() {
        let matches = engine.scan(content: "Amex: 371449635398431")
        let ccMatches = matches.filter { $0.ruleId == "cc" }
        XCTAssertFalse(ccMatches.isEmpty, "Should detect Amex")
    }

    func testCreditCardInvalidLuhn() {
        let matches = engine.scan(content: "Not a card: 4532015112830367")
        let ccMatches = matches.filter { $0.ruleId == "cc" }
        XCTAssertTrue(ccMatches.isEmpty, "Should reject invalid Luhn")
    }

    // MARK: - SSN

    func testSSN() {
        let matches = engine.scan(content: "SSN: 123-45-6789")
        let ssnMatches = matches.filter { $0.ruleId == "ssn" }
        XCTAssertFalse(ssnMatches.isEmpty, "Should detect SSN")
        XCTAssertEqual(ssnMatches.first?.riskLevel, .critical)
    }

    func testSSNInvalidArea() {
        let matches = engine.scan(content: "Invalid: 000-12-3456")
        let ssnMatches = matches.filter { $0.ruleId == "ssn" }
        XCTAssertTrue(ssnMatches.isEmpty, "Should reject area 000")
    }

    func testSSNInvalid666() {
        let matches = engine.scan(content: "Invalid: 666-12-3456")
        let ssnMatches = matches.filter { $0.ruleId == "ssn" }
        XCTAssertTrue(ssnMatches.isEmpty, "Should reject area 666")
    }

    // MARK: - China ID

    func testChinaID() {
        // Valid 18-digit China ID with correct checksum
        let matches = engine.scan(content: "身份证号: 110101199003070011")
        let idMatches = matches.filter { $0.ruleId == "cn_id" }
        XCTAssertFalse(idMatches.isEmpty, "Should detect China ID")
        XCTAssertEqual(idMatches.first?.riskLevel, .critical)
    }

    func testChinaIDInvalidChecksum() {
        let matches = engine.scan(content: "Invalid: 110101199003078030")
        let idMatches = matches.filter { $0.ruleId == "cn_id" }
        XCTAssertTrue(idMatches.isEmpty, "Should reject invalid checksum")
    }

    // MARK: - Email

    func testEmail() {
        let matches = engine.scan(content: "Contact: user@example.com")
        let emailMatches = matches.filter { $0.ruleId == "email" }
        XCTAssertFalse(emailMatches.isEmpty, "Should detect email")
        XCTAssertEqual(emailMatches.first?.riskLevel, .medium)
    }

    // MARK: - China Mobile

    func testChinaMobile() {
        let matches = engine.scan(content: "手机号: 13812345678")
        let phoneMatches = matches.filter { $0.ruleId == "cn_mobile" }
        XCTAssertFalse(phoneMatches.isEmpty, "Should detect China mobile")
    }

    func testChinaMobileInvalidPrefix() {
        let matches = engine.scan(content: "Not a phone: 12345678901")
        let phoneMatches = matches.filter { $0.ruleId == "cn_mobile" }
        XCTAssertTrue(phoneMatches.isEmpty, "Should reject invalid prefix")
    }

    // MARK: - API Keys

    func testOpenAIKey() {
        let matches = engine.scan(content: "Key: sk-proj-abcdefghijklmnopqrstuvwxyz1234567890")
        let apiMatches = matches.filter { $0.ruleId == "api_key" }
        XCTAssertFalse(apiMatches.isEmpty, "Should detect OpenAI key")
        XCTAssertEqual(apiMatches.first?.riskLevel, .critical)
    }

    func testGitHubPAT() {
        let matches = engine.scan(content: "Token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij")
        let apiMatches = matches.filter { $0.ruleId == "api_key" }
        XCTAssertFalse(apiMatches.isEmpty, "Should detect GitHub PAT")
    }

    func testAWSAccessKey() {
        let matches = engine.scan(content: "AWS: AKIAIOSFODNN7EXAMPLE")
        let apiMatches = matches.filter { $0.ruleId == "api_key" }
        XCTAssertFalse(apiMatches.isEmpty, "Should detect AWS key")
    }

    // MARK: - JWT

    func testJWT() {
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        let matches = engine.scan(content: "Token: \(jwt)")
        let jwtMatches = matches.filter { $0.ruleId == "jwt" }
        XCTAssertFalse(jwtMatches.isEmpty, "Should detect JWT")
    }

    // MARK: - Private Key

    func testPrivateKey() {
        let matches = engine.scan(content: "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCA...")
        let pkMatches = matches.filter { $0.ruleId == "private_key" }
        XCTAssertFalse(pkMatches.isEmpty, "Should detect private key header")
    }

    // MARK: - IBAN

    func testIBAN() {
        // Valid German IBAN
        let matches = engine.scan(content: "IBAN: DE89370400440532013000")
        let ibanMatches = matches.filter { $0.ruleId == "iban" }
        XCTAssertFalse(ibanMatches.isEmpty, "Should detect IBAN")
    }

    // MARK: - IP Address

    func testPublicIP() {
        let matches = engine.scan(content: "Server: 8.8.8.8")
        let ipMatches = matches.filter { $0.ruleId == "ip" }
        XCTAssertFalse(ipMatches.isEmpty, "Should detect public IP")
    }

    func testPrivateIPRejected() {
        let matches = engine.scan(content: "Local: 192.168.1.1")
        let ipMatches = matches.filter { $0.ruleId == "ip" }
        XCTAssertTrue(ipMatches.isEmpty, "Should reject private IP")
    }

    func testLoopbackRejected() {
        let matches = engine.scan(content: "Localhost: 127.0.0.1")
        let ipMatches = matches.filter { $0.ruleId == "ip" }
        XCTAssertTrue(ipMatches.isEmpty, "Should reject loopback IP")
    }

    // MARK: - Password

    func testPasswordDetection() {
        let matches = engine.scan(content: "password is MySecret123")
        let pwMatches = matches.filter { $0.ruleId == "password" }
        XCTAssertFalse(pwMatches.isEmpty, "Should detect password pattern")
    }

    func testPasswordChinese() {
        let matches = engine.scan(content: "密码是abc12345")
        let pwMatches = matches.filter { $0.ruleId == "password" }
        XCTAssertFalse(pwMatches.isEmpty, "Should detect Chinese password pattern")
    }

    // MARK: - Ethereum

    func testEthAddress() {
        let matches = engine.scan(content: "ETH: 0x742d35Cc6634C0532925a3b844Bc9e7595f2bD38")
        let ethMatches = matches.filter { $0.ruleId == "eth_addr" }
        XCTAssertFalse(ethMatches.isEmpty, "Should detect Ethereum address")
    }

    // MARK: - Toggle Rules

    func testToggleDisablesRule() {
        let engine = RuleEngine()
        engine.toggleBuiltInRule(id: "email")
        let matches = engine.scan(content: "user@example.com")
        let emailMatches = matches.filter { $0.ruleId == "email" }
        XCTAssertTrue(emailMatches.isEmpty, "Disabled rule should not match")
    }

    func testToggleReenablesRule() {
        let engine = RuleEngine()
        engine.toggleBuiltInRule(id: "email")
        engine.toggleBuiltInRule(id: "email")
        let matches = engine.scan(content: "user@example.com")
        let emailMatches = matches.filter { $0.ruleId == "email" }
        XCTAssertFalse(emailMatches.isEmpty, "Re-enabled rule should match")
    }

    // MARK: - Custom Rules

    func testCustomKeywordRule() {
        let engine = RuleEngine()
        let rule = CustomRule(name: "Test", pattern: "SECRET", patternType: .keyword, riskLevel: .high)
        engine.updateCustomRules([rule])
        let matches = engine.scan(content: "This is a SECRET value")
        let customMatches = matches.filter { $0.detectionLayer == .custom }
        XCTAssertFalse(customMatches.isEmpty, "Custom keyword rule should match")
    }

    func testCustomRegexRule() {
        let engine = RuleEngine()
        let rule = CustomRule(name: "Project Code", pattern: #"PROJ-\d{4}"#, patternType: .regex, riskLevel: .medium)
        engine.updateCustomRules([rule])
        let matches = engine.scan(content: "Task PROJ-1234 is done")
        let customMatches = matches.filter { $0.detectionLayer == .custom }
        XCTAssertFalse(customMatches.isEmpty, "Custom regex rule should match")
    }

    // MARK: - Rule Count

    func testBuiltInRuleCount() {
        XCTAssertGreaterThanOrEqual(engine.allBuiltInRules.count, 40, "Should have 40+ built-in rules")
    }
}
