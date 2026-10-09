import Foundation
import Security

enum KeychainError: LocalizedError {
    case unexpectedStatus(OSStatus)

    var errorDescription: String? {
        switch self {
        case .unexpectedStatus(let status):
            let message = SecCopyErrorMessageString(status, nil) as String? ?? "unknown"
            return "Keychain error \(status): \(message)"
        }
    }
}

/// Minimal generic-password Keychain wrapper.
///
/// Items use `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, so secrets never leave the
/// device (no iCloud Keychain sync, not included in unencrypted backups).
struct KeychainStore: Sendable {
    let service: String

    static let shared = KeychainStore(service: "con.sshapp.RemoteTerminal")

    private func baseQuery(_ account: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
    }

    func set(_ data: Data, account: String) throws {
        try delete(account)
        var query = baseQuery(account)
        query[kSecValueData as String] = data
        query[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else { throw KeychainError.unexpectedStatus(status) }
    }

    func data(for account: String) throws -> Data? {
        var query = baseQuery(account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        switch status {
        case errSecSuccess: return result as? Data
        case errSecItemNotFound: return nil
        default: throw KeychainError.unexpectedStatus(status)
        }
    }

    func delete(_ account: String) throws {
        let status = SecItemDelete(baseQuery(account) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError.unexpectedStatus(status)
        }
    }

    // MARK: String convenience (passwords)

    func setString(_ string: String, account: String) throws {
        try set(Data(string.utf8), account: account)
    }

    func string(for account: String) throws -> String? {
        try data(for: account).flatMap { String(data: $0, encoding: .utf8) }
    }
}
