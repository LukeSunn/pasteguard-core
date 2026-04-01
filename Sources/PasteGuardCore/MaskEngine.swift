import Foundation

/// Applies masking/redaction to sensitive content.
public final class MaskEngine {

    public enum MaskStyle {
        case full           // Replace entirely with ****
        case partial        // Keep first/last chars
        case hash           // Replace with hash prefix
        case custom(String) // Custom replacement text
    }

    public init() {}

    /// Mask sensitive matches within content.
    public func mask(content: String, matches: [DetectionMatch], style: MaskStyle = .partial) -> String {
        guard !matches.isEmpty else { return content }

        let deduped = deduplicateMatches(matches)
        let sorted = deduped.sorted { $0.rangeStart > $1.rangeStart }
        var masked = content

        for match in sorted {
            guard match.rangeStart >= 0,
                  match.rangeEnd <= content.count,
                  match.rangeStart < match.rangeEnd,
                  let startIdx = content.index(content.startIndex, offsetBy: match.rangeStart, limitedBy: content.endIndex),
                  let endIdx = content.index(content.startIndex, offsetBy: match.rangeEnd, limitedBy: content.endIndex) else {
                continue
            }

            let original = String(content[startIdx..<endIdx])
            let replacement: String

            switch style {
            case .full:
                replacement = String(repeating: "*", count: original.count)
            case .partial:
                replacement = original.partialMask()
            case .hash:
                let hashPrefix = String(original.hashValue.description.prefix(8))
                replacement = "[HASH:\(hashPrefix)]"
            case .custom(let text):
                replacement = text
            }

            if let mStartIdx = masked.index(masked.startIndex, offsetBy: match.rangeStart, limitedBy: masked.endIndex),
               let mEndIdx = masked.index(masked.startIndex, offsetBy: match.rangeEnd, limitedBy: masked.endIndex) {
                masked.replaceSubrange(mStartIdx..<mEndIdx, with: replacement)
            }
        }

        return masked
    }

    /// Quick mask for display in previews.
    public func maskForPreview(_ content: String) -> String {
        var result = content
        let patterns: [(String, String)] = [
            (.creditCardPattern, "[CARD]"),
            (.ssnPattern, "[SSN]"),
            (.chinaIDPattern, "[ID]"),
            (.apiKeyPattern, "[API_KEY]"),
        ]
        for (pattern, label) in patterns {
            result = result.masked(pattern: pattern, replacement: label)
        }
        return result
    }

    // MARK: - Deduplication

    private func deduplicateMatches(_ matches: [DetectionMatch]) -> [DetectionMatch] {
        guard matches.count > 1 else { return matches }
        let sorted = matches.sorted { $0.rangeStart < $1.rangeStart }
        var result: [DetectionMatch] = []

        for match in sorted {
            if let last = result.last, match.rangeStart < last.rangeEnd {
                if match.riskLevel > last.riskLevel ||
                   (match.riskLevel == last.riskLevel && (match.rangeEnd - match.rangeStart) > (last.rangeEnd - last.rangeStart)) {
                    result[result.count - 1] = match
                }
            } else {
                result.append(match)
            }
        }
        return result
    }
}
