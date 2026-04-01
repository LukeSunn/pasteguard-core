import Foundation

/// Pattern type for custom rules.
public enum PatternType: String, Codable, Sendable {
    case keyword
    case regex
}

/// A user-defined detection rule.
public struct CustomRule: Codable, Identifiable, Sendable {
    public let id: UUID
    public var name: String
    public var pattern: String
    public var patternType: PatternType
    public var riskLevel: RiskLevel
    public var isEnabled: Bool
    public var maskReplacement: String
    public var createdAt: Date

    public init(
        name: String,
        pattern: String,
        patternType: PatternType = .keyword,
        riskLevel: RiskLevel = .medium,
        isEnabled: Bool = true,
        maskReplacement: String = "[REDACTED]"
    ) {
        self.id = UUID()
        self.name = name
        self.pattern = pattern
        self.patternType = patternType
        self.riskLevel = riskLevel
        self.isEnabled = isEnabled
        self.maskReplacement = maskReplacement
        self.createdAt = .now
    }
}
