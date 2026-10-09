import CryptoKit
import Foundation
import NIOSSH

enum OpenSSHKeyError: LocalizedError, Equatable {
    case notAPrivateKey
    case invalidBase64
    case malformed(String)
    case encryptedKeyNotSupported(cipher: String)
    case unsupportedKeyType(String)
    case multipleKeysNotSupported

    var errorDescription: String? {
        switch self {
        case .notAPrivateKey:
            "This doesn't look like a private key. Paste the contents of a file like ~/.ssh/id_ed25519 (not the .pub file)."
        case .invalidBase64:
            "The key data is not valid base64."
        case .malformed(let detail):
            "The key file is malformed (\(detail))."
        case .encryptedKeyNotSupported(let cipher):
            "Passphrase-protected keys (\(cipher)) aren't supported yet. Remove the passphrase with: ssh-keygen -p -f <keyfile>"
        case .unsupportedKeyType(let type):
            type.contains("rsa")
                ? "RSA keys aren't supported. Generate an Ed25519 key instead (ssh-keygen -t ed25519)."
                : "Unsupported key type: \(type)."
        case .multipleKeysNotSupported:
            "Key files containing multiple keys aren't supported."
        }
    }
}

/// A parsed private key ready to be persisted.
struct ParsedPrivateKey {
    let kind: SSHKeyKind
    /// Raw secret bytes as stored in the Keychain (see `KeyManager.privateKey(kind:secret:)`).
    let secret: Data
    let privateKey: NIOSSHPrivateKey
    let comment: String
}

/// Parsing / encoding of OpenSSH key formats.
enum OpenSSHKeyCodec {
    private static let opensshHeader = "-----BEGIN OPENSSH PRIVATE KEY-----"
    private static let opensshFooter = "-----END OPENSSH PRIVATE KEY-----"
    private static let magic = Array("openssh-key-v1\0".utf8)

    // MARK: Private keys

    static func parsePrivateKey(_ text: String) throws -> ParsedPrivateKey {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)

        if trimmed.contains("BEGIN RSA PRIVATE KEY") { throw OpenSSHKeyError.unsupportedKeyType("ssh-rsa") }
        if trimmed.contains("ENCRYPTED") && trimmed.contains("BEGIN") && !trimmed.contains(opensshHeader) {
            throw OpenSSHKeyError.encryptedKeyNotSupported(cipher: "PEM")
        }
        if trimmed.contains(opensshHeader) { return try parseOpenSSHV1(trimmed) }
        if trimmed.contains("BEGIN EC PRIVATE KEY") || trimmed.contains("BEGIN PRIVATE KEY") {
            return try parsePEMECDSA(trimmed)
        }
        throw OpenSSHKeyError.notAPrivateKey
    }

    private static func parseOpenSSHV1(_ text: String) throws -> ParsedPrivateKey {
        guard let start = text.range(of: opensshHeader), let end = text.range(of: opensshFooter),
              start.upperBound <= end.lowerBound
        else { throw OpenSSHKeyError.notAPrivateKey }
        let body = text[start.upperBound..<end.lowerBound].filter { !$0.isWhitespace }
        guard let data = Data(base64Encoded: String(body)) else { throw OpenSSHKeyError.invalidBase64 }

        var reader = SSHWireReader(Array(data))
        guard try reader.readBytes(magic.count) == magic else { throw OpenSSHKeyError.malformed("bad magic") }
        let cipher = try reader.readString()
        let kdf = try reader.readString()
        _ = try reader.readBlob() // kdf options
        guard cipher == "none" else { throw OpenSSHKeyError.encryptedKeyNotSupported(cipher: cipher) }
        guard kdf == "none" else { throw OpenSSHKeyError.encryptedKeyNotSupported(cipher: kdf) }
        let count = try reader.readUInt32()
        guard count == 1 else { throw OpenSSHKeyError.multipleKeysNotSupported }
        _ = try reader.readBlob() // public key blob (re-derived from the private key)

        var priv = SSHWireReader(try reader.readBlob())
        let check1 = try priv.readUInt32()
        let check2 = try priv.readUInt32()
        guard check1 == check2 else { throw OpenSSHKeyError.malformed("check-int mismatch") }

        let keyType = try priv.readString()
        switch keyType {
        case "ssh-ed25519":
            _ = try priv.readBlob() // 32-byte public key
            let secretAndPublic = try priv.readBlob() // 64 bytes: seed || public
            guard secretAndPublic.count == 64 else { throw OpenSSHKeyError.malformed("ed25519 length") }
            let seed = Data(secretAndPublic[0..<32])
            let comment = try priv.readString()
            let key = try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
            return ParsedPrivateKey(kind: .ed25519, secret: seed, privateKey: NIOSSHPrivateKey(ed25519Key: key), comment: comment)

        case "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521":
            _ = try priv.readString() // curve name
            _ = try priv.readBlob() // public point Q
            let mpint = try priv.readBlob()
            let comment = try priv.readString()
            let (kind, size): (SSHKeyKind, Int) = switch keyType {
            case "ecdsa-sha2-nistp256": (.ecdsaP256, 32)
            case "ecdsa-sha2-nistp384": (.ecdsaP384, 48)
            default: (.ecdsaP521, 66)
            }
            let scalar = try normalizeMPInt(mpint, size: size)
            let key = try KeyManager.privateKey(kind: kind, secret: scalar)
            return ParsedPrivateKey(kind: kind, secret: scalar, privateKey: key, comment: comment)

        default:
            throw OpenSSHKeyError.unsupportedKeyType(keyType)
        }
    }

    private static func parsePEMECDSA(_ pem: String) throws -> ParsedPrivateKey {
        if let k = try? P256.Signing.PrivateKey(pemRepresentation: pem) {
            return ParsedPrivateKey(kind: .ecdsaP256, secret: k.rawRepresentation, privateKey: NIOSSHPrivateKey(p256Key: k), comment: "")
        }
        if let k = try? P384.Signing.PrivateKey(pemRepresentation: pem) {
            return ParsedPrivateKey(kind: .ecdsaP384, secret: k.rawRepresentation, privateKey: NIOSSHPrivateKey(p384Key: k), comment: "")
        }
        if let k = try? P521.Signing.PrivateKey(pemRepresentation: pem) {
            return ParsedPrivateKey(kind: .ecdsaP521, secret: k.rawRepresentation, privateKey: NIOSSHPrivateKey(p521Key: k), comment: "")
        }
        throw OpenSSHKeyError.unsupportedKeyType("PEM (only ECDSA PEM keys are supported)")
    }

    /// SSH mpints are big-endian, may carry a leading 0x00 sign byte, and may be shorter than the field size.
    private static func normalizeMPInt(_ bytes: [UInt8], size: Int) throws -> Data {
        var b = bytes[...]
        while b.count > size, b.first == 0 { b = b.dropFirst() }
        guard b.count <= size else { throw OpenSSHKeyError.malformed("ecdsa scalar length") }
        return Data(repeating: 0, count: size - b.count) + Data(b)
    }

    // MARK: Public keys

    /// `ssh-ed25519 AAAA… comment`
    static func publicKeyString(_ key: NIOSSHPublicKey, comment: String? = nil) -> String {
        let base = String(openSSHPublicKey: key)
        guard let comment, !comment.isEmpty else { return base }
        return "\(base) \(comment.replacingOccurrences(of: " ", with: "-"))"
    }

    /// The algorithm prefix, e.g. `ssh-ed25519`.
    static func keyType(_ key: NIOSSHPublicKey) -> String {
        String(String(openSSHPublicKey: key).split(separator: " ").first ?? "unknown")
    }

    /// `SHA256:<base64 without padding>` — identical to `ssh-keygen -lf`.
    static func fingerprint(_ key: NIOSSHPublicKey) -> String {
        fingerprint(openSSHPublicKey: String(openSSHPublicKey: key)) ?? "unknown"
    }

    static func fingerprint(openSSHPublicKey: String) -> String? {
        let parts = openSSHPublicKey.split(separator: " ")
        guard parts.count >= 2, let blob = Data(base64Encoded: String(parts[1])) else { return nil }
        let digest = Data(SHA256.hash(data: blob)).base64EncodedString()
        return "SHA256:" + digest.trimmingCharacters(in: CharacterSet(charactersIn: "="))
    }
}

/// Reader for the SSH wire encoding (RFC 4251 §5).
struct SSHWireReader {
    private let bytes: [UInt8]
    private var index = 0

    init(_ bytes: [UInt8]) { self.bytes = bytes }

    mutating func readBytes(_ count: Int) throws -> [UInt8] {
        guard count >= 0, index + count <= bytes.count else { throw OpenSSHKeyError.malformed("unexpected end of data") }
        defer { index += count }
        return Array(bytes[index..<index + count])
    }

    mutating func readUInt32() throws -> UInt32 {
        try readBytes(4).reduce(0) { $0 << 8 | UInt32($1) }
    }

    mutating func readBlob() throws -> [UInt8] {
        try readBytes(Int(readUInt32()))
    }

    mutating func readString() throws -> String {
        String(decoding: try readBlob(), as: UTF8.self)
    }
}
