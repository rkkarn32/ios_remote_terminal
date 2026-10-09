import Foundation
import SwiftData

/// A saved SSH destination.
@Model
final class SavedHost {
    @Attribute(.unique) var id: UUID
    var name: String
    var hostname: String
    var port: Int
    var username: String
    /// The `SSHKeyRecord.id` used for public-key auth, if any.
    var keyID: UUID?
    /// Whether a password for this host is stored in the Keychain.
    var hasSavedPassword: Bool
    var createdAt: Date
    var lastConnectedAt: Date?

    init(name: String, hostname: String, port: Int = 22, username: String, keyID: UUID? = nil) {
        self.id = UUID()
        self.name = name
        self.hostname = hostname
        self.port = port
        self.username = username
        self.keyID = keyID
        self.hasSavedPassword = false
        self.createdAt = .now
    }

    var displayName: String { name.isEmpty ? hostname : name }
    var addressDescription: String { port == 22 ? "\(username)@\(hostname)" : "\(username)@\(hostname):\(port)" }
    var passwordKeychainAccount: String { "password.\(id.uuidString)" }
}

/// Supported client key algorithms (SwiftNIO SSH does not support RSA).
enum SSHKeyKind: String, Codable, CaseIterable, Sendable {
    case ed25519
    case ecdsaP256
    case ecdsaP384
    case ecdsaP521
    case secureEnclaveP256

    var displayName: String {
        switch self {
        case .ed25519: "Ed25519"
        case .ecdsaP256: "ECDSA P-256"
        case .ecdsaP384: "ECDSA P-384"
        case .ecdsaP521: "ECDSA P-521"
        case .secureEnclaveP256: "Secure Enclave P-256"
        }
    }
}

/// Metadata for a client key. The private key material lives in the Keychain under `keychainAccount`.
@Model
final class SSHKeyRecord {
    @Attribute(.unique) var id: UUID
    var name: String
    var kindRaw: String
    /// `ssh-ed25519 AAAA… name` — safe to share.
    var publicKeyOpenSSH: String
    /// `SHA256:…` as printed by `ssh-keygen -lf`.
    var fingerprint: String
    var createdAt: Date

    init(id: UUID = UUID(), name: String, kind: SSHKeyKind, publicKeyOpenSSH: String, fingerprint: String) {
        self.id = id
        self.name = name
        self.kindRaw = kind.rawValue
        self.publicKeyOpenSSH = publicKeyOpenSSH
        self.fingerprint = fingerprint
        self.createdAt = .now
    }

    var kind: SSHKeyKind { SSHKeyKind(rawValue: kindRaw) ?? .ed25519 }
    var keychainAccount: String { "key.\(id.uuidString)" }
}

/// A trusted server host key (trust-on-first-use, like `~/.ssh/known_hosts`).
@Model
final class KnownHost {
    /// `hostname:port`
    @Attribute(.unique) var hostPort: String
    var keyType: String
    var publicKeyOpenSSH: String
    var fingerprint: String
    var addedAt: Date

    init(hostPort: String, keyType: String, publicKeyOpenSSH: String, fingerprint: String) {
        self.hostPort = hostPort
        self.keyType = keyType
        self.publicKeyOpenSSH = publicKeyOpenSSH
        self.fingerprint = fingerprint
        self.addedAt = .now
    }

    static func hostPort(_ hostname: String, _ port: Int) -> String { "\(hostname.lowercased()):\(port)" }
}
