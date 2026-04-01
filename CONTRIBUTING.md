# Contributing to PasteGuard Core | 贡献指南

Thank you for your interest in contributing! This guide will help you get started.

感谢您对本项目的关注！本指南将帮助您开始贡献。

## Development Setup | 开发环境

### Requirements
- macOS 13+
- Xcode 15+ or Swift 5.9+

### Build & Test

```bash
# Clone
git clone https://github.com/nicekate/pasteguard-core.git
cd pasteguard-core

# Build
swift build

# Test
swift test
```

## How to Contribute | 如何贡献

### 1. Adding New Detection Rules | 添加新检测规则

This is the most impactful way to contribute. To add a new rule:

这是最有价值的贡献方式。要添加新规则：

**Step 1**: Add the regex pattern to `Sources/PasteGuardCore/Extensions/String+Detection.swift`:

```swift
/// Description of what this pattern matches
public static let myNewPattern = #"your_regex_here"#
```

**Step 2**: Register the rule in `Sources/PasteGuardCore/RuleEngine.swift` inside `loadBuiltInRules()`:

```swift
BuiltInRule(id: "my_new_rule", name: "My New Rule", pattern: .myNewPattern, riskLevel: .high, category: "Category"),
```

**Step 3**: If the rule benefits from checksum validation, add a validator in `String+Detection.swift` and wire it up in `validateMatch()` inside `RuleEngine.swift`.

**Step 4**: Add tests in `Tests/PasteGuardCoreTests/RuleEngineTests.swift`:

```swift
func testMyNewRule() {
    let engine = RuleEngine()

    // True positives (should match)
    let matches1 = engine.scan(content: "valid example here")
    XCTAssertFalse(matches1.isEmpty)
    XCTAssertEqual(matches1.first?.ruleId, "my_new_rule")

    // True negatives (should NOT match)
    let matches2 = engine.scan(content: "similar but not matching")
    XCTAssertTrue(matches2.filter { $0.ruleId == "my_new_rule" }.isEmpty)
}
```

**Requirements for new rules:**
- At least 3 true positive test cases
- At least 3 true negative test cases
- Description of what the pattern detects
- Appropriate risk level and category

### 2. Bug Fixes | Bug 修复

1. Check existing issues to avoid duplicates
2. Create an issue describing the bug
3. Submit a PR referencing the issue
4. Include a test that reproduces the bug

### 3. Performance Improvements | 性能优化

We welcome regex optimizations and algorithmic improvements. Please include benchmarks showing the improvement.

### 4. Documentation | 文档

Improvements to README, code comments, and examples are always welcome.

## Pull Request Process | PR 流程

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-new-rule`
3. Make your changes
4. Run all tests: `swift test`
5. Commit with a descriptive message
6. Push and create a Pull Request

### Commit Message Format

```
type: brief description

- Detail 1
- Detail 2
```

Types: `feat`, `fix`, `docs`, `test`, `perf`, `refactor`

Examples:
```
feat: add Japan My Number detection rule
fix: reduce false positives in US routing number pattern
docs: add Korean phone pattern examples
test: add edge cases for IBAN validation
```

## Code Style | 代码风格

- Follow existing code patterns in the project
- Use `public` access level for all public API
- Add doc comments for public types and methods
- Use raw strings (`#"..."#`) for regex patterns
- Include `Sendable` conformance where applicable

## Rule Categories | 规则分类

When adding rules, use one of these categories:

| Category | Description |
|----------|-------------|
| `General` | Common PII (email, phone, IP) |
| `Identity` | Government-issued IDs |
| `Financial` | Payment and banking |
| `Crypto` | Cryptocurrency |
| `Credential` | API keys, tokens, secrets |
| `Healthcare` | Medical identifiers |
| `Vehicle` | Vehicle-related |

## Risk Levels | 风险等级

| Level | When to Use |
|-------|-------------|
| `low` | Publicly available info (public IP) |
| `medium` | Semi-public PII (email, phone, license plate) |
| `high` | Important PII (passport, bank card, NI number) |
| `critical` | Highly sensitive (SSN, credit card, private key, seed phrase) |

## License | 许可

By contributing, you agree that your contributions will be licensed under the MIT License.

## Questions? | 有问题？

Open a GitHub Issue or start a Discussion. We're happy to help!

如有任何问题，请在 GitHub 创建 Issue 或在 Discussions 中提问。
