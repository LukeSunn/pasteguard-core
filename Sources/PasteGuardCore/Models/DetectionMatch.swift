import Foundation

/// Represents a single match found by the detection engine.
public struct DetectionMatch: Codable, Identifiable, Sendable {
    public let id: UUID
    public let ruleId: String
    public let ruleName: String
    public let matchedText: String
    public let rangeStart: Int
    public let rangeEnd: Int
    public let riskLevel: RiskLevel
    public let maskSuggestion: String
    public let detectionLayer: DetectionLayer

    public enum DetectionLayer: String, Codable, Sendable {
        case regex = "L1_Regex"
        case ner = "L2_NER"
        case llm = "L3_LLM"
        case custom = "Custom"
    }

    public init(
        ruleId: String,
        ruleName: String,
        matchedText: String,
        rangeStart: Int,
        rangeEnd: Int,
        riskLevel: RiskLevel,
        maskSuggestion: String = "[REDACTED]",
        detectionLayer: DetectionLayer = .regex
    ) {
        self.id = UUID()
        self.ruleId = ruleId
        self.ruleName = ruleName
        self.matchedText = matchedText
        self.rangeStart = rangeStart
        self.rangeEnd = rangeEnd
        self.riskLevel = riskLevel
        self.maskSuggestion = maskSuggestion
        self.detectionLayer = detectionLayer
    }
}
