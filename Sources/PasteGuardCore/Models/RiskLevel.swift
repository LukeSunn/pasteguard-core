import Foundation

/// Risk severity level for detected sensitive content.
public enum RiskLevel: String, Codable, CaseIterable, Comparable, Sendable {
    case none = "none"
    case low = "low"
    case medium = "medium"
    case high = "high"
    case critical = "critical"

    public var displayName: String {
        switch self {
        case .none: return "Safe"
        case .low: return "Low"
        case .medium: return "Medium"
        case .high: return "High"
        case .critical: return "Critical"
        }
    }

    public var numericValue: Int {
        switch self {
        case .none: return 0
        case .low: return 1
        case .medium: return 2
        case .high: return 3
        case .critical: return 4
        }
    }

    public static func < (lhs: RiskLevel, rhs: RiskLevel) -> Bool {
        lhs.numericValue < rhs.numericValue
    }
}
