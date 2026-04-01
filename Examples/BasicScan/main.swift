import PasteGuardCore

// ============================================
// PasteGuard Core — Basic Scan Example
// ============================================

let engine = RuleEngine()
let maskEngine = MaskEngine()

// Sample content with various sensitive data
let content = """
Employee Record:
Name: John Smith
Email: john.smith@company.com
Phone: (555) 123-4567
SSN: 234-56-7890
Credit Card: 4532015112830366

Server Config:
IP: 8.8.8.8
DB: postgres://admin:secret@db.example.com:5432/production
API Key: sk-proj-abcdefghijklmnopqrstuvwxyz1234567890
JWT: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U

China Data:
手机号: 13812345678
身份证: 110101199003078035
"""

print("=== Scanning for sensitive data ===\n")

let matches = engine.scan(content: content)

print("Found \(matches.count) sensitive items:\n")

// Group by category
let grouped = Dictionary(grouping: matches) { match in
    engine.allBuiltInRules.first { $0.id == match.ruleId }?.category ?? "Custom"
}

for (category, categoryMatches) in grouped.sorted(by: { $0.key < $1.key }) {
    print("[\(category)]")
    for match in categoryMatches {
        print("  \(match.ruleName): \(match.matchedText) — \(match.riskLevel.displayName)")
    }
    print()
}

// Mask the content
print("=== Masked Output ===\n")
let masked = maskEngine.mask(content: content, matches: matches, style: .partial)
print(masked)
