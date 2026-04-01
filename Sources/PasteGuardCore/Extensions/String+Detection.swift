import Foundation

extension String {

    // MARK: - PII Detection Patterns

    /// Credit card: Visa/MC/Amex/Discover with optional separators. Validated by Luhn.
    public static let creditCardPattern = #"(?<!\d)(?:4[0-9]{3}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{1,4}|5[1-5][0-9]{2}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}|3[47][0-9]{2}[\s\-]?[0-9]{6}[\s\-]?[0-9]{5}|6(?:011|5[0-9]{2})[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4})(?!\d)"#

    /// SSN: requires dashes, excludes invalid area (000/666/9xx), group (00), serial (0000)
    public static let ssnPattern = #"(?<!\d)(?!000|666|9\d\d)\d{3}\-(?!00)\d{2}\-(?!0000)\d{4}(?!\d)"#

    /// Email: standard format with 2-63 char TLD
    public static let emailPattern = #"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,63}\b"#

    /// Phone (US): requires area code with parens OR country code prefix
    public static let phonePattern = #"(?<!\d)(?:\+1[\s.\-]?)?\(\d{3}\)[\s.\-]?\d{3}[\s.\-]?\d{4}(?!\d)"#

    /// API key: only known service prefixes (OpenAI sk-, GitHub ghp_, AWS AKIA, Google AIza, etc.)
    public static let apiKeyPattern = #"(?:sk\-(?:proj\-)?[a-zA-Z0-9]{20,}|pk_(?:live|test)_[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{20,}|glpat\-[a-zA-Z0-9\-_]{20,}|xoxb\-[0-9A-Za-z\-]+|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z\-_]{35})"#

    /// IP Address: validates each octet 0-255, filtered for public IPs in RuleEngine
    public static let ipAddressPattern = #"(?<!\d)(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(?!\d)"#

    /// China mobile: 11 digits with valid carrier prefixes
    public static let chinaMobilePattern = #"(?<!\d)1(?:3\d|4[5-9]|5[0-35-9]|6[2567]|7[0-8]|8\d|9[0-35-9])\d{8}(?!\d)"#

    /// China ID card: 18 digits with valid area code, date (YYYYMMDD), and check digit.
    public static let chinaIDPattern = #"(?<!\d)[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx](?!\d)"#

    /// Bank card: 16-19 digits, common BIN prefixes (UnionPay 62, Visa 4, MC 5).
    public static let bankCardPattern = #"(?<!\d)(?:62[0-9]{14,17}|4[0-9]{15}|5[1-5][0-9]{14})(?!\d)"#

    /// Passport: CN (E/G + 8 digits)
    public static let passportPattern = #"(?<!\w)[EeGg]\d{8}(?!\w)"#

    // MARK: - International PII Patterns

    /// IBAN: International Bank Account Number
    public static let ibanPattern = #"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"#

    /// US ITIN: Individual Taxpayer Identification Number (9XX-XX-XXXX)
    public static let itinPattern = #"(?<!\d)9\d{2}\-\d{2}\-\d{4}(?!\d)"#

    /// US EIN: Employer Identification Number (XX-XXXXXXX)
    public static let einPattern = #"(?<!\d)\d{2}\-\d{7}(?!\d)"#

    /// US Routing Number: 9-digit ABA routing transit number.
    public static let usRoutingPattern = #"(?<!\d)(?:0[1-9]|[1-2]\d|3[0-2])\d{7}(?!\d)"#

    /// UK NHS Number: 10 digits with spaces (3-3-4 format).
    public static let ukNHSPattern = #"(?<!\d)\d{3}[\s\-]?\d{3}[\s\-]?\d{4}(?!\d)"#

    /// UK National Insurance Number: 2 letters + 6 digits + 1 letter
    public static let ukNINOPattern = #"(?<!\w)[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]\d{6}[A-D](?!\w)"#

    /// Germany Personalausweis (ID): 10 alphanumeric, starts with letter
    public static let deIDPattern = #"(?<!\w)[CFGHJKLMNPRTVWXYZ][CFGHJKLMNPRTVWXYZ0-9]\d{8}(?!\w)"#

    /// France NIR (INSEE / Social Security)
    public static let frNIRPattern = #"(?<!\d)[12]\d{2}(?:0[1-9]|1[0-2])\d{5}\d{3}(?:\d{2})?(?!\d)"#

    /// Spain DNI: 8 digits + 1 letter
    public static let esDNIPattern = #"(?<!\w)\d{8}[A-HJ-NP-TV-Z](?!\w)"#

    /// Spain NIE: X/Y/Z + 7 digits + 1 letter
    public static let esNIEPattern = #"(?<!\w)[XYZ]\d{7}[A-HJ-NP-TV-Z](?!\w)"#

    /// Italy Codice Fiscale: 16 alphanumeric
    public static let itFiscalCodePattern = #"(?<!\w)[A-Z]{6}\d{2}[A-EHLMPR-T]\d{2}[A-Z]\d{3}[A-Z](?!\w)"#

    /// Australia ABN: 11 digits.
    public static let auABNPattern = #"(?<!\d)\d{2}[\s]?\d{3}[\s]?\d{3}[\s]?\d{3}(?!\d)"#

    /// Australia TFN: 8-9 digits.
    public static let auTFNPattern = #"(?<!\d)\d{3}[\s\-]?\d{3}[\s\-]?\d{2,3}(?!\d)"#

    /// Singapore NRIC/FIN: [STFGM] + 7 digits + 1 letter
    public static let sgNRICPattern = #"(?<!\w)[STFGM]\d{7}[A-Z](?!\w)"#

    /// China Unified Social Credit Code: 18 chars
    public static let cnSocialCreditPattern = #"(?<!\w)[0-9A-HJ-NP-RTUW-Y]{2}\d{6}[0-9A-HJ-NP-RTUW-Y]{10}(?!\w)"#

    /// China HK/Macau Travel Permit: C/W + 8 digits
    public static let cnHKMacauPermitPattern = #"(?<!\w)[CWcw]\d{8}(?!\w)"#

    /// China Taiwan Travel Permit: L + 8 digits
    public static let cnTaiwanPermitPattern = #"(?<!\w)[Ll]\d{8}(?!\w)"#

    // MARK: - Credential & Secret Patterns

    /// JWT Token: starts with eyJ (Base64-encoded JSON header)
    public static let jwtPattern = #"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"#

    /// Private Key / Certificate header
    public static let privateKeyPattern = #"-----BEGIN\s(?:RSA\s)?(?:PRIVATE\sKEY|CERTIFICATE|EC\sPRIVATE\sKEY|DSA\sPRIVATE\sKEY|OPENSSH\sPRIVATE\sKEY|PGP\sPRIVATE\sKEY\sBLOCK)-----"#

    /// Database connection string: postgres://, mysql://, mongodb://, redis://
    public static let dbConnectionPattern = #"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql):\/\/[^\s'"]{10,}"#

    /// OAuth Bearer Token
    public static let bearerTokenPattern = #"[Bb]earer\s+[A-Za-z0-9\-._~+/]+=*"#

    /// Webhook URL: Slack, Discord, etc.
    public static let webhookURLPattern = #"https:\/\/(?:hooks\.slack\.com\/services|discord(?:app)?\.com\/api\/webhooks|outlook\.office\.com\/webhook)\/[A-Za-z0-9_/\-]+"#

    /// Generic high-entropy secret: env variable assignments
    public static let envSecretPattern = #"(?:SECRET|PASSWORD|TOKEN|PRIVATE_KEY|API_KEY|APIKEY|ACCESS_KEY|AUTH)\s*[=:]\s*['"]?[A-Za-z0-9+/=\-_.]{8,}['"]?"#

    /// Password in natural language
    public static let passwordPattern = #"(?i)(?:password|passwd|pwd|pass(?:phrase)?|密码|口令)\s*(?:is|[:=：是为])+\s*['"]?([^\s'"，。,\.]{4,})"#

    // MARK: - Cryptocurrency Patterns

    /// Bitcoin Legacy Address: Base58Check, starts with 1 or 3
    public static let btcAddressPattern = #"(?<!\w)[13][a-km-zA-HJ-NP-Z1-9]{24,33}(?!\w)"#

    /// Bitcoin Bech32 Address: starts with bc1
    public static let btcBech32Pattern = #"(?<!\w)bc1[ac-hj-np-z02-9]{38,58}(?!\w)"#

    /// Ethereum Address: 0x followed by 40 hex chars
    public static let ethAddressPattern = #"(?<!\w)0x[0-9a-fA-F]{40}(?!\w)"#

    /// Solana Address: Base58, 32-44 chars
    public static let solAddressPattern = #"(?<!\w)[1-9A-HJ-NP-Za-km-z]{32,44}(?!\w)"#

    /// Crypto Private Key (Hex): 64 hex chars (256-bit key)
    public static let cryptoPrivateKeyPattern = #"(?<!\w)[0-9a-fA-F]{64}(?!\w)"#

    /// BIP-39 Seed Phrase: 12 or 24 lowercase words separated by spaces
    public static let seedPhrasePattern = #"(?<!\w)(?:abandon|ability|able|about|above|absent|absorb|abstract|absurd|abuse|access|accident|account|accuse|achieve|acid|acoustic|acquire|across|action|actor|actress|actual|adapt|add|addict|address|adjust|admit|adult|advance|advice|aerobic|affair|afford|afraid|again|age|agent|agree|ahead|aim|air|airport|aisle|alarm|album|alcohol|alert|alien|all|alley|allow|almost|alone|alpha|already|also|alter|always|amateur|amazing|among|amount|amused|analyst|anchor|ancient|anger|angle|angry|animal|ankle|announce|annual|another|answer|antenna|antique|anxiety|any|apart|apology|appear|apple|approve|april|arch|arctic|area|arena|argue|arm|armed|armor|army|around|arrange|arrest|arrive|arrow|art|artefact|artist|artwork|ask|aspect|assault|asset|assist|assume|asthma|athlete|atom|attack|attend|attitude|attract|auction|audit|august|aunt|author|auto|autumn|average|avocado|avoid|awake|aware|awesome|awful|awkward|axis)\b(?:\s+\b(?:abandon|ability|able|about|above|absent|absorb|abstract|absurd|abuse|access|accident|account|accuse|achieve|acid|acoustic|acquire|across|action|actor|actress|actual|adapt|add|addict|address|adjust|admit|adult|advance|advice|aerobic|affair|afford|afraid|again|age|agent|agree|ahead|aim|air|airport|aisle|alarm|album|alcohol|alert|alien|all|alley|allow|almost|alone|alpha|already|also|alter|always|amateur|amazing|among|amount|amused|analyst|anchor|ancient|anger|angle|angry|animal|ankle|announce|annual|another|answer|antenna|antique|anxiety|any|apart|apology|appear|apple|approve|april|arch|arctic|area|arena|argue|arm|armed|armor|army|around|arrange|arrest|arrive|arrow|art|artefact|artist|artwork|ask|aspect|assault|asset|assist|assume|asthma|athlete|atom|attack|attend|attitude|attract|auction|audit|august|aunt|author|auto|autumn|average|avocado|avoid|awake|aware|awesome|awful|awkward|axis)\b){11,23}"#

    /// SWIFT/BIC Code: 8 or 11 alphanumeric
    public static let swiftCodePattern = #"(?<!\w)[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?(?!\w)"#

    // MARK: - Healthcare Patterns

    /// US NPI (National Provider Identifier): 10 digits starting with 1 or 2.
    public static let usNPIPattern = #"(?<!\d)[12]\d{9}(?!\d)"#

    /// US DEA Number
    public static let usDeaPattern = #"(?<!\w)[ABCDEFGHJKMabcdefghjkm][A-Za-z][0-9]{7}(?!\w)"#

    /// SSH Private Key header
    public static let sshPrivateKeyPattern = #"-----BEGIN\s(?:OPENSSH|RSA|DSA|EC|ENCRYPTED)\s(?:PRIVATE\s)?KEY-----"#

    // MARK: - Vehicle & Transport Patterns

    /// China license plate
    public static let cnLicensePlatePattern = #"(?<!\w)[京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤川青藏琼宁][A-HJ-NP-Z][A-HJ-NP-Z0-9]{4,5}[A-HJ-NP-Z0-9挂学警港澳](?!\w)"#

    /// VIN (Vehicle Identification Number): 17 characters (no I, O, Q).
    public static let vinPattern = #"(?<!\w)[A-HJ-NPR-Z0-9]{17}(?!\w)"#

    // MARK: - Pattern Matching Helpers

    public func matches(pattern: String) -> [NSTextCheckingResult] {
        guard let regex = try? NSRegularExpression(pattern: pattern, options: []) else {
            return []
        }
        return regex.matches(in: self, range: NSRange(startIndex..., in: self))
    }

    public func containsMatch(pattern: String) -> Bool {
        guard let regex = try? NSRegularExpression(pattern: pattern, options: []) else {
            return false
        }
        return regex.firstMatch(in: self, range: NSRange(startIndex..., in: self)) != nil
    }

    public func extractMatches(pattern: String) -> [String] {
        let results = matches(pattern: pattern)
        return results.compactMap { result in
            guard let range = Range(result.range, in: self) else { return nil }
            return String(self[range])
        }
    }

    // MARK: - Checksum Validation

    /// Luhn algorithm validation for credit/debit card numbers
    public func luhnValid() -> Bool {
        let digits = self.replacingOccurrences(of: "[\\s\\-]", with: "", options: .regularExpression)
            .compactMap { $0.wholeNumberValue }
        guard digits.count >= 13 && digits.count <= 19 else { return false }

        var sum = 0
        var isSecond = false
        for i in stride(from: digits.count - 1, through: 0, by: -1) {
            var d = digits[i]
            if isSecond {
                d *= 2
                if d > 9 { d -= 9 }
            }
            sum += d
            isSecond.toggle()
        }
        return sum % 10 == 0
    }

    /// China 18-digit ID card checksum validation (GB 11643-1999)
    public func chinaIDValid() -> Bool {
        let cleaned = self.uppercased()
        guard cleaned.count == 18 else { return false }

        let weights = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
        let checkChars: [Character] = ["1", "0", "X", "9", "8", "7", "6", "5", "4", "3", "2"]

        let chars = Array(cleaned)
        var sum = 0
        for i in 0..<17 {
            guard let digit = chars[i].wholeNumberValue else { return false }
            sum += digit * weights[i]
        }

        let checkIndex = sum % 11
        return chars[17] == checkChars[checkIndex]
    }

    /// Validate IBAN checksum using ISO 7064 Mod 97-10
    public func ibanValid() -> Bool {
        let cleaned = self.replacingOccurrences(of: "[\\s\\-]", with: "", options: .regularExpression).uppercased()
        guard cleaned.count >= 15, cleaned.count <= 34 else { return false }
        let rearranged = String(cleaned.dropFirst(4)) + String(cleaned.prefix(4))
        var numericString = ""
        for char in rearranged {
            if let digit = char.wholeNumberValue {
                numericString += String(digit)
            } else if let asciiValue = char.asciiValue, asciiValue >= 65, asciiValue <= 90 {
                numericString += String(Int(asciiValue) - 55)
            } else {
                return false
            }
        }
        var remainder = 0
        for char in numericString {
            guard let digit = char.wholeNumberValue else { return false }
            remainder = (remainder * 10 + digit) % 97
        }
        return remainder == 1
    }

    /// Validate UK NHS Number using Mod 11 checksum
    public func nhsValid() -> Bool {
        let digits = self.replacingOccurrences(of: "[\\s\\-]", with: "", options: .regularExpression)
            .compactMap { $0.wholeNumberValue }
        guard digits.count == 10 else { return false }
        let weights = [10, 9, 8, 7, 6, 5, 4, 3, 2]
        var sum = 0
        for i in 0..<9 { sum += digits[i] * weights[i] }
        let remainder = sum % 11
        let checkDigit = 11 - remainder
        if checkDigit == 11 { return digits[9] == 0 }
        if checkDigit == 10 { return false }
        return digits[9] == checkDigit
    }

    /// Validate US ABA Routing Number checksum
    public func routingNumberValid() -> Bool {
        let digits = self.compactMap { $0.wholeNumberValue }
        guard digits.count == 9 else { return false }
        let checksum = 3 * (digits[0] + digits[3] + digits[6]) +
                        7 * (digits[1] + digits[4] + digits[7]) +
                        1 * (digits[2] + digits[5] + digits[8])
        return checksum % 10 == 0
    }

    /// Validate Spain DNI letter
    public func dniLetterValid() -> Bool {
        guard self.count == 9 else { return false }
        let chars = Array(self)
        let letterTable: [Character] = ["T","R","W","A","G","M","Y","F","P","D","X","B","N","J","Z","S","Q","V","H","L","C","K","E"]
        let numberPart = String(chars[0..<8])
        guard let num = Int(numberPart) else { return false }
        return chars[8] == letterTable[num % 23]
    }

    /// Validate Australia ABN checksum
    public func abnValid() -> Bool {
        let digits = self.replacingOccurrences(of: "\\s", with: "", options: .regularExpression)
            .compactMap { $0.wholeNumberValue }
        guard digits.count == 11 else { return false }
        var d = digits
        d[0] = d[0] - 1
        let weights = [10, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19]
        var sum = 0
        for i in 0..<11 { sum += d[i] * weights[i] }
        return sum % 89 == 0
    }

    /// Validate US NPI using Luhn with prefix 80840
    public func npiValid() -> Bool {
        let digits = self.compactMap { $0.wholeNumberValue }
        guard digits.count == 10 else { return false }
        let prefixed = [8, 0, 8, 4, 0] + digits
        var sum = 0
        var isSecond = false
        for i in stride(from: prefixed.count - 1, through: 0, by: -1) {
            var d = prefixed[i]
            if isSecond {
                d *= 2
                if d > 9 { d -= 9 }
            }
            sum += d
            isSecond.toggle()
        }
        return sum % 10 == 0
    }

    /// Validate VIN check digit (position 9)
    public func vinValid() -> Bool {
        let vin = self.uppercased()
        guard vin.count == 17 else { return false }
        guard !vin.contains("I"), !vin.contains("O"), !vin.contains("Q") else { return false }

        let transliteration: [Character: Int] = [
            "A":1,"B":2,"C":3,"D":4,"E":5,"F":6,"G":7,"H":8,
            "J":1,"K":2,"L":3,"M":4,"N":5,"P":7,"R":9,
            "S":2,"T":3,"U":4,"V":5,"W":6,"X":7,"Y":8,"Z":9,
            "0":0,"1":1,"2":2,"3":3,"4":4,"5":5,"6":6,"7":7,"8":8,"9":9
        ]
        let weights = [8,7,6,5,4,3,2,10,0,9,8,7,6,5,4,3,2]
        let chars = Array(vin)

        var sum = 0
        for (i, c) in chars.enumerated() {
            guard let value = transliteration[c] else { return false }
            sum += value * weights[i]
        }
        let remainder = sum % 11
        let checkChar = chars[8]
        if remainder == 10 {
            return checkChar == "X"
        } else {
            return checkChar == Character("\(remainder)")
        }
    }

    // MARK: - Masking

    public func masked(pattern: String, replacement: String = "****") -> String {
        guard let regex = try? NSRegularExpression(pattern: pattern, options: []) else {
            return self
        }
        return regex.stringByReplacingMatches(in: self, range: NSRange(startIndex..., in: self), withTemplate: replacement)
    }

    public func partialMask(keepFirst: Int = 2, keepLast: Int = 2) -> String {
        guard count > keepFirst + keepLast else { return String(repeating: "*", count: count) }
        let prefix = String(self.prefix(keepFirst))
        let suffix = String(self.suffix(keepLast))
        let maskLength = count - keepFirst - keepLast
        return prefix + String(repeating: "*", count: maskLength) + suffix
    }

    public func truncatedPreview(maxLength: Int = 100) -> String {
        if count <= maxLength { return self }
        return String(prefix(maxLength)) + "..."
    }
}
