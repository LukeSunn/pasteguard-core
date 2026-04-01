<div align="center">

# 🛡️ PasteGuard Core

**Open-source sensitive data detection engine for Swift**

[![Swift](https://img.shields.io/badge/Swift-5.9+-orange.svg)](https://swift.org)
[![Platform](https://img.shields.io/badge/Platform-macOS%2013%2B%20%7C%20iOS%2016%2B-blue.svg)]()
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![CI](https://github.com/LukeSunn/pasteguard-core/actions/workflows/ci.yml/badge.svg)](https://github.com/LukeSunn/pasteguard-core/actions/workflows/ci.yml)

[English](#english) | [中文](#中文)

</div>

---

<a name="english"></a>

## What is PasteGuard Core?

 PasteGuard Core is a high-performance, offline sensitive data detection engine written in pure Swift. It powers the PasteGuard macOS app — a clipboard privacy guard that protects your sensitive information when using AI tools.

This library provides the **L1 Regex Detection Layer** — scanning text for 40+ types of sensitive data with algorithmic validation to minimize false positives.

### Supported Data Types

| Category | Types |
|----------|-------|
| **Identity** | SSN, China ID (18-digit), Passport, UK NI/NHS, DE ID, FR NIR, ES DNI/NIE, IT Fiscal Code, AU TFN, SG NRIC, China USCC, HK/Macau/Taiwan Permits |
| **Financial** | Credit Cards (Visa/MC/Amex/Discover), Bank Cards (UnionPay), IBAN, US Routing, US EIN, AU ABN, SWIFT/BIC |
| **Crypto** | Bitcoin (Legacy + Bech32), Ethereum, Solana addresses, Private Keys (Hex), BIP-39 Seed Phrases |
| **Credentials** | API Keys (OpenAI/GitHub/AWS/Google/Slack/GitLab), JWT Tokens, SSH/PGP Private Keys, Database URLs, Bearer Tokens, Webhook URLs, Env Secrets |
| **Healthcare** | US NPI, US DEA Number |
| **Vehicle** | China License Plates, VIN |
| **General** | Email, Phone (US), China Mobile, IP Address, Passwords |

### Validation Algorithms

Every match is verified against known checksum algorithms to eliminate false positives:

- **Luhn** — Credit cards, bank cards, NPI
- **Mod 97 (ISO 7064)** — IBAN
- **Mod 11** — UK NHS
- **GB 11643-1999** — China ID card
- **ABA Checksum** — US Routing Numbers
- **DNI Letter Check** — Spain DNI
- **ABN Checksum** — Australia ABN
- **VIN Check Digit** — Vehicle Identification Numbers
- **IP Range Filter** — Excludes private/reserved IPs

## Installation

### Swift Package Manager

Add to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/LukeSunn/pasteguard-core.git", from: "1.0.0")
]
```

Then add `"PasteGuardCore"` to your target's dependencies.

### Xcode

File → Add Package Dependencies → Enter the repository URL.

## Quick Start

```swift
import PasteGuardCore

// Create a rule engine
let engine = RuleEngine()

// Scan text for sensitive data
let content = "My card number is 4532015112830366 and SSN is 123-45-6789"
let matches = engine.scan(content: content)

for match in matches {
    print("\(match.ruleName): \(match.matchedText) [\(match.riskLevel.displayName)]")
}
// Output:
// Credit Card: 45**********0366 [Critical]
// US SSN: 12*****789 [Critical]
```

### Masking

```swift
let maskEngine = MaskEngine()

// Partial mask (default): keeps first 2 and last 2 chars
let masked = maskEngine.mask(content: content, matches: matches, style: .partial)
print(masked)  // "My card number is 45**************66 and SSN is 12*******89"

// Full mask
let full = maskEngine.mask(content: content, matches: matches, style: .full)
print(full)  // "My card number is **************** and SSN is ***********"
```

### Custom Rules

```swift
let engine = RuleEngine()

// Add keyword-based rule
let rule = CustomRule(
    name: "AWS Secret Key",
    pattern: "AKIA",
    patternType: .keyword,
    riskLevel: .critical
)
engine.updateCustomRules([rule])

// Add regex-based rule
let regexRule = CustomRule(
    name: "Internal Project Code",
    pattern: #"PROJ-\d{4,6}"#,
    patternType: .regex,
    riskLevel: .medium
)
engine.updateCustomRules([rule, regexRule])
```

### File Scanning

```swift
let reader = FileContentReader()

if let content = reader.readContent(from: fileURL) {
    let matches = engine.scan(content: content)
    print("Found \(matches.count) sensitive items")
}
```

Supported formats: TXT, MD, JSON, CSV, XML, HTML, YAML, PDF, RTF, DOCX, XLSX, PPTX, Swift, Python, JS, and 30+ more.

### Disable Specific Rules

```swift
let engine = RuleEngine()

// Disable email detection
engine.toggleBuiltInRule(id: "email")

// Check all available rules
for rule in engine.allBuiltInRules {
    let status = engine.isBuiltInRuleEnabled(rule.id) ? "ON" : "OFF"
    print("[\(status)] \(rule.name) (\(rule.category))")
}
```

## Architecture

```
PasteGuardCore
├── RuleEngine          — 40+ regex rules with checksum validation
├── MaskEngine          — Content masking/redaction
├── FileContentReader   — Multi-format file text extraction
├── PGLogger            — Unified logging (os.log)
├── Models/
│   ├── RiskLevel       — none/low/medium/high/critical
│   ├── DetectionMatch  — Match result with position and metadata
│   └── CustomRule      — User-defined detection rules
└── Extensions/
    └── String+Detection — 40+ regex patterns + checksum validators
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines. We welcome:

- New detection rules (with test cases)
- Checksum validators for new document types
- Bug fixes and performance improvements
- Documentation improvements

## License

MIT License — see [LICENSE](LICENSE) for details.

---

<a name="中文"></a>

## 什么是 PasteGuard Core？

PasteGuard Core 是一个高性能、纯离线的敏感数据检测引擎，使用纯 Swift 编写。它是 PasteGuard macOS 应用的核心组件 — 一款在您使用 AI 工具时保护敏感信息的剪贴板隐私卫士。

本库提供 **L1 正则检测层** — 扫描文本中 40+ 种敏感数据类型，并通过算法验证减少误报。

### 支持的数据类型

| 分类 | 类型 |
|------|------|
| **身份证件** | 美国 SSN、中国身份证（18位）、护照、英国 NI/NHS、德国身份证、法国 NIR、西班牙 DNI/NIE、意大利税号、澳大利亚 TFN、新加坡 NRIC、统一社会信用代码、港澳台通行证 |
| **金融信息** | 信用卡（Visa/MC/Amex/Discover）、银行卡（银联）、IBAN、美国路由号、EIN、澳大利亚 ABN、SWIFT/BIC |
| **加密货币** | 比特币（Legacy + Bech32）、以太坊、Solana 地址、私钥（Hex）、BIP-39 助记词 |
| **凭证密钥** | API Key（OpenAI/GitHub/AWS/Google/Slack/GitLab）、JWT 令牌、SSH/PGP 私钥、数据库连接串、Bearer Token、Webhook URL、环境变量密钥 |
| **医疗健康** | 美国 NPI、DEA 编号 |
| **车辆交通** | 中国车牌号、VIN 车架号 |
| **通用信息** | 邮箱、美国电话、中国手机号、IP 地址、密码 |

### 校验算法

每个匹配结果都会通过已知校验算法进行验证，以消除误报：

- **Luhn 算法** — 信用卡、银行卡、NPI
- **Mod 97 (ISO 7064)** — IBAN
- **Mod 11** — 英国 NHS
- **GB 11643-1999** — 中国身份证
- **ABA 校验** — 美国路由号
- **DNI 字母校验** — 西班牙 DNI
- **ABN 校验** — 澳大利亚 ABN
- **VIN 校验位** — 车辆识别号
- **IP 范围过滤** — 排除私有/保留 IP

## 安装

### Swift Package Manager

在 `Package.swift` 中添加：

```swift
dependencies: [
    .package(url: "https://github.com/LukeSunn/pasteguard-core.git", from: "1.0.0")
]
```

然后将 `"PasteGuardCore"` 添加到 target 的依赖中。

### Xcode

菜单 File → Add Package Dependencies → 输入仓库 URL。

## 快速开始

```swift
import PasteGuardCore

// 创建规则引擎
let engine = RuleEngine()

// 扫描文本中的敏感数据
let content = "我的卡号是 4532015112830366，身份证号 110101199003078035"
let matches = engine.scan(content: content)

for match in matches {
    print("\(match.ruleName): \(match.matchedText) [\(match.riskLevel.displayName)]")
}
// 输出:
// Credit Card: 45**********0366 [Critical]
// China ID Card: 11**************35 [Critical]
```

### 脱敏处理

```swift
let maskEngine = MaskEngine()

// 部分脱敏（默认）：保留首尾各 2 个字符
let masked = maskEngine.mask(content: content, matches: matches, style: .partial)

// 完全脱敏
let full = maskEngine.mask(content: content, matches: matches, style: .full)
```

### 自定义规则

```swift
let engine = RuleEngine()

// 添加关键词规则
let rule = CustomRule(
    name: "内部项目编号",
    pattern: "PROJ-",
    patternType: .keyword,
    riskLevel: .medium
)

// 添加正则规则
let regexRule = CustomRule(
    name: "AWS 密钥",
    pattern: #"AKIA[0-9A-Z]{16}"#,
    patternType: .regex,
    riskLevel: .critical
)

engine.updateCustomRules([rule, regexRule])
```

### 文件扫描

```swift
let reader = FileContentReader()

if let content = reader.readContent(from: fileURL) {
    let matches = engine.scan(content: content)
    print("发现 \(matches.count) 处敏感信息")
}
```

支持格式：TXT、MD、JSON、CSV、XML、HTML、YAML、PDF、RTF、DOCX、XLSX、PPTX、Swift、Python、JS 等 30+ 种。

## 架构

```
PasteGuardCore
├── RuleEngine          — 40+ 条正则规则 + 校验算法
├── MaskEngine          — 内容脱敏/遮盖
├── FileContentReader   — 多格式文件文本提取
├── PGLogger            — 统一日志（os.log）
├── Models/
│   ├── RiskLevel       — none/low/medium/high/critical
│   ├── DetectionMatch  — 匹配结果（含位置和元数据）
│   └── CustomRule      — 用户自定义检测规则
└── Extensions/
    └── String+Detection — 40+ 正则模式 + 校验验证器
```

## 参与贡献

请参阅 [CONTRIBUTING.md](CONTRIBUTING.md)。我们欢迎：

- 新的检测规则（需附带测试用例）
- 新文档类型的校验验证器
- Bug 修复和性能优化
- 文档改进

## 许可证

MIT License — 详见 [LICENSE](LICENSE)。
