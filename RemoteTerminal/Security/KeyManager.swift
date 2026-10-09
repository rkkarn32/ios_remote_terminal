import CryptoKit
import Foundation
import NIOSSH
import SwiftData

enum KeyManagerError: LocalizedError {
    case secureEnclaveUnavailable
    case missingKeyMaterial(String)

    var errorDescription: String? {
        switch self {
        case .secureEnclaveUnavailable: "This device has no Secure Enclave (Simulator?)."
        case .missingKeyMaterial(let name): "The private key for “\(name)” is missing from the Keychain."
        }
    }
}

/// Creates, imports, loads and deletes client keys. Metadata goes to SwiftData, secrets to the Keychain.
enum KeyManager {
    static var isSecureEnclaveAvailable: Bool { SecureEnclave.isAvailable }

    /// Generates new key material. Returns the NIOSSH key and the secret bytes to store.
    static func generate(kind: SSHKeyKind) throws -> (NIOSSHPrivateKey, Data) {
        switch kind {
        case .ed25519:
            let k = Curve25519.Signing.PrivateKey()
            return (NIOSSHPrivateKey(ed25519Key: k), k.rawRepresentation)
        case .ecdsaP256:
            let k = P256.Signing.PrivateKey()
            return (NIOSSHPrivateKey(p256Key: k), k.rawRepresentation)
        case .ecdsaP384:
            let k = P384.Signing.PrivateKey()
            return (NIOSSHPrivateKey(p384Key: k), k.rawRepresentation)
        case .ecdsaP521:
            let k = P521.Signing.PrivateKey()
            return (NIOSSHPrivateKey(p521Key: k), k.rawRepresentation)
        case .secureEnclaveP256:
            guard SecureEnclave.isAvailable else { throw KeyManagerError.secureEnclaveUnavailable }
            // dataRepresentation is an opaque, device-bound handle; the private key never leaves the Secure Enclave.
            let k = try SecureEnclave.P256.Signing.PrivateKey()
            return (NIOSSHPrivateKey(secureEnclaveP256Key: k), k.dataRepresentation)
        }
    }

    /// Reconstructs a NIOSSH key from stored secret bytes.
    static func privateKey(kind: SSHKeyKind, secret: Data) throws -> NIOSSHPrivateKey {
        switch kind {
        case .ed25519: NIOSSHPrivateKey(ed25519Key: try .init(rawRepresentation: secret))
        case .ecdsaP256: NIOSSHPrivateKey(p256Key: try .init(rawRepresentation: secret))
        case .ecdsaP384: NIOSSHPrivateKey(p384Key: try .init(rawRepresentation: secret))
        case .ecdsaP521: NIOSSHPrivateKey(p521Key: try .init(rawRepresentation: secret))
        case .secureEnclaveP256: NIOSSHPrivateKey(secureEnclaveP256Key: try .init(dataRepresentation: secret))
        }
    }

    // MARK: Persistence

    @MainActor
    @discardableResult
    static func generateAndSave(name: String, kind: SSHKeyKind, context: ModelContext,
                                keychain: KeychainStore = .shared) throws -> SSHKeyRecord {
        let (key, secret) = try generate(kind: kind)
        return try save(name: name, kind: kind, key: key, secret: secret, context: context, keychain: keychain)
    }

    @MainActor
    @discardableResult
    static func importAndSave(text: String, name: String, context: ModelContext,
                              keychain: KeychainStore = .shared) throws -> SSHKeyRecord {
        let parsed = try OpenSSHKeyCodec.parsePrivateKey(text)
        let finalName = name.isEmpty ? (parsed.comment.isEmpty ? "Imported key" : parsed.comment) : name
        return try save(name: finalName, kind: parsed.kind, key: parsed.privateKey, secret: parsed.secret,
                        context: context, keychain: keychain)
    }

    @MainActor
    private static func save(name: String, kind: SSHKeyKind, key: NIOSSHPrivateKey, secret: Data,
                             context: ModelContext, keychain: KeychainStore) throws -> SSHKeyRecord {
        let comment = "\(name)@RemoteTerminal"
        let record = SSHKeyRecord(
            name: name, kind: kind,
            publicKeyOpenSSH: OpenSSHKeyCodec.publicKeyString(key.publicKey, comment: comment),
            fingerprint: OpenSSHKeyCodec.fingerprint(key.publicKey))
        try keychain.set(secret, account: record.keychainAccount)
        context.insert(record)
        try context.save()
        return record
    }

    static func loadPrivateKey(account: String, kind: SSHKeyKind, name: String,
                               keychain: KeychainStore = .shared) throws -> NIOSSHPrivateKey {
        guard let secret = try keychain.data(for: account) else { throw KeyManagerError.missingKeyMaterial(name) }
        return try privateKey(kind: kind, secret: secret)
    }

    @MainActor
    static func delete(_ record: SSHKeyRecord, context: ModelContext, keychain: KeychainStore = .shared) throws {
        try keychain.delete(record.keychainAccount)
        context.delete(record)
        try context.save()
    }
}
