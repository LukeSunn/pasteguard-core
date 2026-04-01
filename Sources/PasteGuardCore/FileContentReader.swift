import Foundation
#if canImport(PDFKit)
import PDFKit
#endif

/// Reads and extracts text content from various document file formats.
public final class FileContentReader {

    /// Maximum file size to read (10 MB)
    private let maxFileSize: Int = 10 * 1024 * 1024

    /// Supported file extensions
    public static let supportedExtensions: Set<String> = [
        "txt", "md", "markdown", "json", "csv", "xml", "html", "htm",
        "yaml", "yml", "toml", "ini", "cfg", "conf", "log",
        "rtf", "rtfd", "pdf",
        "plist", "strings",
        "swift", "py", "js", "ts", "java", "c", "cpp", "h", "m", "rs",
        "go", "rb", "php", "sh", "bash", "zsh", "sql", "r",
        "env", "gitignore", "dockerfile",
        "docx", "xlsx", "pptx",
    ]

    public init() {}

    /// Extracts text content from a file URL.
    public func readContent(from url: URL) -> String? {
        let ext = url.pathExtension.lowercased()

        guard FileManager.default.isReadableFile(atPath: url.path) else {
            PGLogger.warning("File not readable: \(url.lastPathComponent)")
            return nil
        }

        guard let attrs = try? FileManager.default.attributesOfItem(atPath: url.path),
              let fileSize = attrs[.size] as? Int,
              fileSize <= maxFileSize else {
            PGLogger.warning("File too large or unreadable: \(url.lastPathComponent)")
            return nil
        }

        switch ext {
        #if canImport(PDFKit)
        case "pdf":
            return readPDF(from: url)
        #endif
        case "rtf", "rtfd":
            return readRTF(from: url)
        case "docx":
            return readDocx(from: url)
        case "xlsx":
            return readXlsx(from: url)
        case "pptx":
            return readPptx(from: url)
        default:
            return readPlainText(from: url)
        }
    }

    /// Check if the file extension is supported.
    public static func isSupported(_ url: URL) -> Bool {
        supportedExtensions.contains(url.pathExtension.lowercased())
    }

    // MARK: - Readers

    private func readPlainText(from url: URL) -> String? {
        try? String(contentsOf: url, encoding: .utf8)
    }

    #if canImport(PDFKit)
    private func readPDF(from url: URL) -> String? {
        guard let document = PDFDocument(url: url) else { return nil }
        var text = ""
        for i in 0..<min(document.pageCount, 50) {
            if let page = document.page(at: i), let pageText = page.string {
                text += pageText + "\n"
            }
        }
        return text.isEmpty ? nil : text
    }
    #endif

    private func readRTF(from url: URL) -> String? {
        guard let data = try? Data(contentsOf: url) else { return nil }
        let attrString = try? NSAttributedString(
            data: data,
            options: [.documentType: NSAttributedString.DocumentType.rtf],
            documentAttributes: nil
        )
        return attrString?.string
    }

    // MARK: - Office Open XML (macOS only)

    #if os(macOS)
    private func readDocx(from url: URL) -> String? {
        extractTextFromZip(url: url, xmlPaths: ["word/document.xml"])
    }

    private func readXlsx(from url: URL) -> String? {
        let sheetPaths = discoverFilesInZip(url: url, prefix: "xl/worksheets/sheet", suffix: ".xml")
        let allPaths = ["xl/sharedStrings.xml"] + sheetPaths
        return extractTextFromZip(url: url, xmlPaths: allPaths)
    }

    private func readPptx(from url: URL) -> String? {
        let slidePaths = discoverFilesInZip(url: url, prefix: "ppt/slides/slide", suffix: ".xml")
        guard !slidePaths.isEmpty else { return nil }
        return extractTextFromZip(url: url, xmlPaths: slidePaths)
    }

    private func extractTextFromZip(url: URL, xmlPaths: [String]) -> String? {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/unzip")
        process.arguments = ["-o", url.path] + xmlPaths + ["-d", tempDir.path]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice

        do {
            try process.run()
            process.waitUntilExit()
        } catch {
            return nil
        }

        var allText: [String] = []
        for xmlPath in xmlPaths {
            let xmlFile = tempDir.appendingPathComponent(xmlPath)
            guard let xmlData = try? Data(contentsOf: xmlFile),
                  let xmlString = String(data: xmlData, encoding: .utf8) else {
                continue
            }
            let text = stripXMLTags(xmlString)
            if !text.isEmpty {
                allText.append(text)
            }
        }

        return allText.isEmpty ? nil : allText.joined(separator: "\n")
    }

    private func discoverFilesInZip(url: URL, prefix: String, suffix: String) -> [String] {
        let pipe = Pipe()
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/unzip")
        process.arguments = ["-l", url.path]
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice

        do {
            try process.run()
            process.waitUntilExit()
        } catch {
            return []
        }

        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        guard let output = String(data: data, encoding: .utf8) else { return [] }

        return output.components(separatedBy: .newlines).compactMap { line in
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard let path = trimmed.components(separatedBy: .whitespaces).last,
                  path.hasPrefix(prefix), path.hasSuffix(suffix) else { return nil }
            return path
        }
    }

    private func stripXMLTags(_ xml: String) -> String {
        guard let regex = try? NSRegularExpression(pattern: "<[^>]+>", options: []) else { return xml }
        let range = NSRange(xml.startIndex..., in: xml)
        return regex.stringByReplacingMatches(in: xml, range: range, withTemplate: " ")
            .replacingOccurrences(of: "&amp;", with: "&")
            .replacingOccurrences(of: "&lt;", with: "<")
            .replacingOccurrences(of: "&gt;", with: ">")
            .replacingOccurrences(of: "&quot;", with: "\"")
            .replacingOccurrences(of: "&apos;", with: "'")
            .components(separatedBy: .whitespacesAndNewlines)
            .filter { !$0.isEmpty }
            .joined(separator: " ")
    }
    #else
    private func readDocx(from url: URL) -> String? { nil }
    private func readXlsx(from url: URL) -> String? { nil }
    private func readPptx(from url: URL) -> String? { nil }
    #endif
}
