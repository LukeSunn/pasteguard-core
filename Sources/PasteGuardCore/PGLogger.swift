import Foundation
import os.log

/// Centralized logging for PasteGuard Core.
public struct PGLogger {

    private static let subsystem = "com.pasteguard.core"
    private static let logger = os.Logger(subsystem: subsystem, category: "general")

    public static func info(_ message: String) {
        logger.info("\(message, privacy: .public)")
    }

    public static func warning(_ message: String) {
        logger.warning("\(message, privacy: .public)")
    }

    public static func error(_ message: String) {
        logger.error("\(message, privacy: .public)")
    }

    public static func debug(_ message: String) {
        #if DEBUG
        logger.debug("\(message, privacy: .public)")
        #endif
    }
}
