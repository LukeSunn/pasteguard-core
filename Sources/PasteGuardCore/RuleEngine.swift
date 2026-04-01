import Foundation

/// L1 regex-based rule engine. Scans content against 40+ built-in rules and user-defined custom rules.
///
/// Built-in rules cover:
/// - Identity documents (SSN, China ID, passport, NRIC, etc.)
/// - Financial data (credit cards, IBAN, bank cards, routing numbers)
/// - Credentials (API keys, JWT, SSH keys, database URLs)
/// - Cryptocurrency (BTC/ETH addresses, seed phrases, private keys)
/// - Healthcare (NPI, DEA numbers)
/// - Vehicle info (VIN, license plates)
///
/// Each match is validated with algorithmic checksums (Luhn, Mod97, etc.)
/// to minimize false positives.
public final class RuleEngine {

    public struct BuiltInRule: Sendable {
        public let id: String
        public let name: String
        public let pattern: String
        public let riskLevel: RiskLevel
        public let category: String

        public init(id: String, name: String, pattern: String, riskLevel: RiskLevel, category: String) {
            self.id = id
            self.name = name
            self.pattern = pattern
            self.riskLevel = riskLevel
            self.category = category
        }
    }

    private var builtInRules: [BuiltInRule] = []
    private var customRules: [CustomRule] = []

    /// IDs of disabled built-in rules.
    public private(set) var disabledBuiltInRuleIds: Set<String> = []

    public var builtInRuleCount: Int { builtInRules.count - disabledBuiltInRuleIds.count }
    public var customRuleCount: Int { customRules.filter(\.isEnabled).count }

    /// All built-in rules (read-only access).
    public var allBuiltInRules: [BuiltInRule] { builtInRules }

    public init() {
        loadBuiltInRules()
    }

    public func toggleBuiltInRule(id: String) {
        if disabledBuiltInRuleIds.contains(id) {
            disabledBuiltInRuleIds.remove(id)
        } else {
            disabledBuiltInRuleIds.insert(id)
        }
    }

    public func isBuiltInRuleEnabled(_ id: String) -> Bool {
        !disabledBuiltInRuleIds.contains(id)
    }

    public func updateCustomRules(_ rules: [CustomRule]) {
        self.customRules = rules
    }

    /// Scan content against all enabled built-in and custom rules.
    /// Returns an array of `DetectionMatch` for every sensitive item found.
    public func scan(content: String) -> [DetectionMatch] {
        var matches: [DetectionMatch] = []

        // Scan built-in rules
        for rule in builtInRules {
            guard !disabledBuiltInRuleIds.contains(rule.id) else { continue }
            let found = content.matches(pattern: rule.pattern)
            for result in found {
                guard let range = Range(result.range, in: content) else { continue }
                let matchedText = String(content[range])

                // Post-match validation to eliminate false positives
                guard validateMatch(ruleId: rule.id, text: matchedText) else { continue }

                matches.append(DetectionMatch(
                    ruleId: rule.id,
                    ruleName: rule.name,
                    matchedText: matchedText.partialMask(),
                    rangeStart: result.range.location,
                    rangeEnd: result.range.location + result.range.length,
                    riskLevel: rule.riskLevel,
                    maskSuggestion: "****",
                    detectionLayer: .regex
                ))
            }
        }

        // Scan custom rules
        for rule in customRules where rule.isEnabled {
            let pattern: String
            switch rule.patternType {
            case .keyword:
                let escaped = NSRegularExpression.escapedPattern(for: rule.pattern)
                pattern = "\\b\(escaped)\\b"
            case .regex:
                pattern = rule.pattern
            }

            let found = content.matches(pattern: pattern)
            for result in found {
                guard let range = Range(result.range, in: content) else { continue }
                let matchedText = String(content[range])
                matches.append(DetectionMatch(
                    ruleId: rule.id.uuidString,
                    ruleName: rule.name,
                    matchedText: matchedText.partialMask(),
                    rangeStart: result.range.location,
                    rangeEnd: result.range.location + result.range.length,
                    riskLevel: rule.riskLevel,
                    maskSuggestion: rule.maskReplacement,
                    detectionLayer: .custom
                ))
            }
        }

        return matches
    }

    private func loadBuiltInRules() {
        builtInRules = [
            // General
            BuiltInRule(id: "email", name: "Email Address", pattern: .emailPattern, riskLevel: .medium, category: "General"),
            BuiltInRule(id: "phone", name: "Phone Number (US)", pattern: .phonePattern, riskLevel: .medium, category: "General"),
            BuiltInRule(id: "cn_mobile", name: "China Mobile", pattern: .chinaMobilePattern, riskLevel: .medium, category: "General"),
            BuiltInRule(id: "ip", name: "IP Address", pattern: .ipAddressPattern, riskLevel: .low, category: "General"),
            BuiltInRule(id: "password", name: "Password", pattern: .passwordPattern, riskLevel: .critical, category: "General"),

            // Identity Documents
            BuiltInRule(id: "ssn", name: "US SSN", pattern: .ssnPattern, riskLevel: .critical, category: "Identity"),
            BuiltInRule(id: "us_itin", name: "US ITIN", pattern: .itinPattern, riskLevel: .critical, category: "Identity"),
            BuiltInRule(id: "cn_id", name: "China ID Card", pattern: .chinaIDPattern, riskLevel: .critical, category: "Identity"),
            BuiltInRule(id: "cn_hk_macau", name: "HK/Macau Permit", pattern: .cnHKMacauPermitPattern, riskLevel: .high, category: "Identity"),
            BuiltInRule(id: "cn_taiwan", name: "Taiwan Permit", pattern: .cnTaiwanPermitPattern, riskLevel: .high, category: "Identity"),
            BuiltInRule(id: "passport", name: "Passport (CN)", pattern: .passportPattern, riskLevel: .high, category: "Identity"),
            BuiltInRule(id: "uk_nino", name: "UK NI Number", pattern: .ukNINOPattern, riskLevel: .high, category: "Identity"),
            BuiltInRule(id: "uk_nhs", name: "UK NHS Number", pattern: .ukNHSPattern, riskLevel: .high, category: "Identity"),
            BuiltInRule(id: "de_id", name: "DE Personalausweis", pattern: .deIDPattern, riskLevel: .high, category: "Identity"),
            BuiltInRule(id: "fr_nir", name: "FR NIR (INSEE)", pattern: .frNIRPattern, riskLevel: .high, category: "Identity"),
            BuiltInRule(id: "es_dni", name: "ES DNI", pattern: .esDNIPattern, riskLevel: .high, category: "Identity"),
            BuiltInRule(id: "es_nie", name: "ES NIE", pattern: .esNIEPattern, riskLevel: .high, category: "Identity"),
            BuiltInRule(id: "it_fiscal", name: "IT Codice Fiscale", pattern: .itFiscalCodePattern, riskLevel: .high, category: "Identity"),
            BuiltInRule(id: "au_tfn", name: "AU TFN", pattern: .auTFNPattern, riskLevel: .high, category: "Identity"),
            BuiltInRule(id: "sg_nric", name: "SG NRIC/FIN", pattern: .sgNRICPattern, riskLevel: .high, category: "Identity"),
            BuiltInRule(id: "cn_social_credit", name: "China USCC", pattern: .cnSocialCreditPattern, riskLevel: .high, category: "Identity"),

            // Financial
            BuiltInRule(id: "cc", name: "Credit Card", pattern: .creditCardPattern, riskLevel: .critical, category: "Financial"),
            BuiltInRule(id: "bank_card", name: "Bank Card", pattern: .bankCardPattern, riskLevel: .high, category: "Financial"),
            BuiltInRule(id: "iban", name: "IBAN", pattern: .ibanPattern, riskLevel: .critical, category: "Financial"),
            BuiltInRule(id: "us_routing", name: "US Routing Number", pattern: .usRoutingPattern, riskLevel: .high, category: "Financial"),
            BuiltInRule(id: "us_ein", name: "US EIN", pattern: .einPattern, riskLevel: .high, category: "Financial"),
            BuiltInRule(id: "au_abn", name: "AU ABN", pattern: .auABNPattern, riskLevel: .high, category: "Financial"),
            BuiltInRule(id: "swift_code", name: "SWIFT/BIC Code", pattern: .swiftCodePattern, riskLevel: .medium, category: "Financial"),

            // Cryptocurrency
            BuiltInRule(id: "btc_addr", name: "Bitcoin Address", pattern: .btcAddressPattern, riskLevel: .critical, category: "Crypto"),
            BuiltInRule(id: "eth_addr", name: "Ethereum Address", pattern: .ethAddressPattern, riskLevel: .critical, category: "Crypto"),
            BuiltInRule(id: "btc_bech32", name: "Bitcoin Bech32", pattern: .btcBech32Pattern, riskLevel: .critical, category: "Crypto"),
            BuiltInRule(id: "sol_addr", name: "Solana Address", pattern: .solAddressPattern, riskLevel: .critical, category: "Crypto"),
            BuiltInRule(id: "crypto_privkey", name: "Crypto Private Key", pattern: .cryptoPrivateKeyPattern, riskLevel: .critical, category: "Crypto"),
            BuiltInRule(id: "seed_phrase", name: "Seed Phrase (BIP-39)", pattern: .seedPhrasePattern, riskLevel: .critical, category: "Crypto"),

            // Credentials & Secrets
            BuiltInRule(id: "api_key", name: "API Key / Secret", pattern: .apiKeyPattern, riskLevel: .critical, category: "Credential"),
            BuiltInRule(id: "jwt", name: "JWT Token", pattern: .jwtPattern, riskLevel: .critical, category: "Credential"),
            BuiltInRule(id: "private_key", name: "Private Key / Cert", pattern: .privateKeyPattern, riskLevel: .critical, category: "Credential"),
            BuiltInRule(id: "db_conn", name: "Database URL", pattern: .dbConnectionPattern, riskLevel: .critical, category: "Credential"),
            BuiltInRule(id: "bearer_token", name: "Bearer Token", pattern: .bearerTokenPattern, riskLevel: .high, category: "Credential"),
            BuiltInRule(id: "webhook", name: "Webhook URL", pattern: .webhookURLPattern, riskLevel: .high, category: "Credential"),
            BuiltInRule(id: "env_secret", name: "Env Secret", pattern: .envSecretPattern, riskLevel: .high, category: "Credential"),
            BuiltInRule(id: "ssh_key", name: "SSH Private Key", pattern: .sshPrivateKeyPattern, riskLevel: .critical, category: "Credential"),

            // Healthcare
            BuiltInRule(id: "us_npi", name: "US NPI", pattern: .usNPIPattern, riskLevel: .high, category: "Healthcare"),
            BuiltInRule(id: "us_dea", name: "US DEA Number", pattern: .usDeaPattern, riskLevel: .high, category: "Healthcare"),

            // Vehicle & Transport
            BuiltInRule(id: "cn_plate", name: "China License Plate", pattern: .cnLicensePlatePattern, riskLevel: .medium, category: "Vehicle"),
            BuiltInRule(id: "vin", name: "VIN", pattern: .vinPattern, riskLevel: .high, category: "Vehicle"),
        ]
    }

    // MARK: - Post-Match Validation

    private func validateMatch(ruleId: String, text: String) -> Bool {
        switch ruleId {
        case "cc":        return text.luhnValid()
        case "bank_card": return text.luhnValid()
        case "cn_id":     return text.chinaIDValid()
        case "ip":        return isValidPublicIP(text)
        case "iban":      return text.ibanValid()
        case "uk_nhs":    return text.nhsValid()
        case "us_routing": return text.routingNumberValid()
        case "es_dni":    return text.dniLetterValid()
        case "au_abn":    return text.abnValid()
        case "us_npi":    return text.npiValid()
        case "vin":       return text.vinValid()
        default:          return true
        }
    }

    private func isValidPublicIP(_ ip: String) -> Bool {
        let parts = ip.split(separator: ".").compactMap { Int($0) }
        guard parts.count == 4, parts.allSatisfy({ (0...255).contains($0) }) else { return false }
        if parts[0] == 0 || parts[0] == 10 || parts[0] == 127 { return false }
        if parts[0] == 172 && (16...31).contains(parts[1]) { return false }
        if parts[0] == 192 && parts[1] == 168 { return false }
        if parts[0] == 169 && parts[1] == 254 { return false }
        if parts[0] >= 224 { return false }
        return true
    }
}
