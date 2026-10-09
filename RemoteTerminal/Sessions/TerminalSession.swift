import Foundation
import NIOSSH
import Observation
import SwiftData
import SwiftTerm
import UIKit

/// A host-key trust question awaiting the user's answer.
struct HostKeyPrompt: Identifiable {
    enum Kind { case unknown, changed(previousFingerprint: String) }
    let id = UUID()
    let hostPort: String
    let keyType: String
    let fingerprint: String
    let kind: Kind
}

/// An interactive password prompt awaiting user input.
struct PasswordPrompt: Identifiable {
    let id = UUID()
    let username: String
    let hostname: String
    let isRetry: Bool
}

/// Immutable snapshot of what to connect to (decoupled from SwiftData).
struct ConnectionTarget: Sendable {
    let hostID: UUID
    let name: String
    let hostname: String
    let port: Int
    let username: String
    let keyID: UUID?
    let passwordAccount: String?

    @MainActor
    init(_ host: SavedHost) {
        hostID = host.id
        name = host.displayName
        hostname = host.hostname
        port = host.port
        username = host.username
        keyID = host.keyID
        passwordAccount = host.hasSavedPassword ? host.passwordKeychainAccount : nil
    }
}

/// One interactive SSH session with its own terminal emulator (scrollback survives tab switches).
@MainActor
@Observable
final class TerminalSession: Identifiable {
    enum State: Equatable {
        case connecting
        case awaitingHostKeyTrust
        case connected
        case disconnected(String?)
    }

    let id = UUID()
    let target: ConnectionTarget
    var title: String
    var state: State = .connecting
    var hostKeyPrompt: HostKeyPrompt?
    var passwordPrompt: PasswordPrompt?

    @ObservationIgnored let terminalView: TerminalView
    @ObservationIgnored private let container: ModelContainer
    @ObservationIgnored private var client: SSHClient?
    @ObservationIgnored private var shell: SSHShell?
    @ObservationIgnored private var hostKeyContinuation: CheckedContinuation<Bool, Never>?
    @ObservationIgnored private var passwordContinuation: CheckedContinuation<String?, Never>?
    @ObservationIgnored private var connectTask: Task<Void, Never>?

    init(target: ConnectionTarget, container: ModelContainer) {
        self.target = target
        self.container = container
        self.title = target.name
        let font = UIFont.monospacedSystemFont(ofSize: 13, weight: .regular)
        self.terminalView = TerminalView(frame: CGRect(x: 0, y: 0, width: 400, height: 600), font: font)
        configureTerminalView()
    }

    private func configureTerminalView() {
        terminalView.terminalDelegate = self
        terminalView.nativeBackgroundColor = .black
        terminalView.nativeForegroundColor = UIColor(white: 0.92, alpha: 1)
        terminalView.optionAsMetaKey = true
        terminalView.autocorrectionType = .no
        terminalView.autocapitalizationType = .none
        terminalView.smartQuotesType = .no
        terminalView.smartDashesType = .no
        terminalView.spellCheckingType = .no
        terminalView.keyboardAppearance = .dark
        let pinch = UIPinchGestureRecognizer(target: PinchProxy.shared, action: #selector(PinchProxy.handle(_:)))
        terminalView.addGestureRecognizer(pinch)
    }

    var isConnected: Bool { state == .connected }

    // MARK: Lifecycle

    func start() {
        connectTask?.cancel()
        connectTask = Task { await connect() }
    }

    func reconnect() {
        teardown()
        print(local: "\r\n\u{1B}[90m— reconnecting —\u{1B}[0m\r\n")
        start()
    }

    func disconnect() {
        connectTask?.cancel()
        teardown()
        state = .disconnected(nil)
    }

    private func teardown() {
        resolveHostKeyPrompt(trust: false)
        resolvePasswordPrompt(password: nil, saveToKeychain: false)
        shell?.close()
        client?.close()
        shell = nil
        client = nil
    }

    private func connect() async {
        state = .connecting
        print(local: "\u{1B}[90mConnecting to \(target.username)@\(target.hostname):\(target.port)…\u{1B}[0m\r\n")
        do {
            let (privateKey, password) = try loadCredentials()
            let client = try await SSHClient.connect(
                host: target.hostname, port: target.port, username: target.username,
                privateKey: privateKey, password: password,
                passwordPromptHandler: { [weak self] user, isRetry in
                    await self?.promptForPassword(user: user, isRetry: isRetry)
                },
                hostKeyHandler: { [weak self] key in
                    await self?.decideHostKey(key) ?? .reject("Session closed")
                })
            if Task.isCancelled { client.close(); return }
            self.client = client

            let terminal = terminalView.getTerminal()
            let shell = try await client.openShell(
                cols: terminal.cols, rows: terminal.rows,
                onOutput: { [weak self] bytes in
                    // DispatchQueue.main preserves chunk ordering.
                    DispatchQueue.main.async { MainActor.assumeIsolated { self?.terminalView.feed(byteArray: bytes[...]) } }
                },
                onClose: { [weak self] status in
                    DispatchQueue.main.async { MainActor.assumeIsolated { self?.shellDidClose(exitStatus: status) } }
                })
            self.shell = shell
            state = .connected
            markConnected()
        } catch {
            guard !Task.isCancelled else { return }
            teardown()
            let message = error.localizedDescription
            state = .disconnected(message)
            print(local: "\r\n\u{1B}[31m✗ \(message)\u{1B}[0m\r\n")
        }
    }

    private func shellDidClose(exitStatus: Int?) {
        guard state == .connected else { return }
        client?.close()
        client = nil
        shell = nil
        let reason = exitStatus.map { "Shell exited with status \($0)." } ?? "Connection closed."
        state = .disconnected(reason)
        print(local: "\r\n\u{1B}[90m— \(reason) —\u{1B}[0m\r\n")
    }

    private func print(local text: String) {
        terminalView.feed(text: text)
    }

    // MARK: Credentials

    private func loadCredentials() throws -> (NIOSSHPrivateKey?, String?) {
        var key: NIOSSHPrivateKey?
        if let keyID = target.keyID {
            let descriptor = FetchDescriptor<SSHKeyRecord>(predicate: #Predicate { $0.id == keyID })
            if let record = try container.mainContext.fetch(descriptor).first {
                key = try KeyManager.loadPrivateKey(account: record.keychainAccount, kind: record.kind, name: record.name)
            }
        }
        let password = try target.passwordAccount.flatMap { try KeychainStore.shared.string(for: $0) }
        return (key, password)
    }

    private func markConnected() {
        let hostID = target.hostID
        let descriptor = FetchDescriptor<SavedHost>(predicate: #Predicate { $0.id == hostID })
        if let host = try? container.mainContext.fetch(descriptor).first {
            host.lastConnectedAt = .now
            try? container.mainContext.save()
        }
    }

    // MARK: Host key verification (TOFU)

    private func decideHostKey(_ key: NIOSSHPublicKey) async -> HostKeyDecision {
        let hostPort = KnownHost.hostPort(target.hostname, target.port)
        let presented = String(openSSHPublicKey: key)
        let fingerprint = OpenSSHKeyCodec.fingerprint(key)
        let keyType = OpenSSHKeyCodec.keyType(key)
        let context = container.mainContext
        let descriptor = FetchDescriptor<KnownHost>(predicate: #Predicate { $0.hostPort == hostPort })
        let existing = try? context.fetch(descriptor).first

        if let existing, existing.publicKeyOpenSSH == presented {
            return .trust
        }

        let kind: HostKeyPrompt.Kind = existing.map { .changed(previousFingerprint: $0.fingerprint) } ?? .unknown
        state = .awaitingHostKeyTrust
        let trusted = await withCheckedContinuation { continuation in
            hostKeyContinuation = continuation
            hostKeyPrompt = HostKeyPrompt(hostPort: hostPort, keyType: keyType, fingerprint: fingerprint, kind: kind)
        }
        guard trusted else {
            return .reject(existing == nil ? "Not trusted by user." : "Host key changed — possible man-in-the-middle attack.")
        }

        if let existing { context.delete(existing) }
        context.insert(KnownHost(hostPort: hostPort, keyType: keyType, publicKeyOpenSSH: presented, fingerprint: fingerprint))
        try? context.save()
        state = .connecting
        return .trust
    }

    func resolveHostKeyPrompt(trust: Bool) {
        hostKeyPrompt = nil
        hostKeyContinuation?.resume(returning: trust)
        hostKeyContinuation = nil
    }

    // MARK: Password prompting

    private func promptForPassword(user: String, isRetry: Bool) async -> String? {
        await withCheckedContinuation { continuation in
            passwordContinuation = continuation
            passwordPrompt = PasswordPrompt(username: user, hostname: target.hostname, isRetry: isRetry)
        }
    }

    func resolvePasswordPrompt(password: String?, saveToKeychain: Bool) {
        if let password, saveToKeychain {
            let account = target.passwordAccount ?? "password.\(target.hostID.uuidString)"
            try? KeychainStore.shared.setString(password, account: account)
            let hostID = target.hostID
            let descriptor = FetchDescriptor<SavedHost>(predicate: #Predicate { $0.id == hostID })
            if let host = try? container.mainContext.fetch(descriptor).first {
                host.hasSavedPassword = true
                try? container.mainContext.save()
            }
        }
        passwordPrompt = nil
        passwordContinuation?.resume(returning: password)
        passwordContinuation = nil
    }
}

// MARK: - SwiftTerm delegate

extension TerminalSession: @preconcurrency TerminalViewDelegate {
    func send(source: TerminalView, data: ArraySlice<UInt8>) {
        if let shell {
            shell.write(data)
        } else if case .disconnected = state, data.contains(13) {
            reconnect() // press Return to reconnect
        }
    }

    func sizeChanged(source: TerminalView, newCols: Int, newRows: Int) {
        shell?.resize(cols: newCols, rows: newRows)
    }

    func setTerminalTitle(source: TerminalView, title: String) {
        self.title = title.isEmpty ? target.name : title
    }

    func hostCurrentDirectoryUpdate(source: TerminalView, directory: String?) {}
    func scrolled(source: TerminalView, position: Double) {}

    func requestOpenLink(source: TerminalView, link: String, params: [String: String]) {
        if let url = URL(string: link) { UIApplication.shared.open(url) }
    }

    func bell(source: TerminalView) {
        UIImpactFeedbackGenerator(style: .light).impactOccurred()
    }

    func clipboardCopy(source: TerminalView, content: Data) {
        if let string = String(data: content, encoding: .utf8) { UIPasteboard.general.string = string }
    }

    func clipboardRead(source: TerminalView) -> Data? {
        UIPasteboard.general.string.map { Data($0.utf8) }
    }

    func iTermContent(source: TerminalView, content: ArraySlice<UInt8>) {}
    func rangeChanged(source: TerminalView, startY: Int, endY: Int) {}
}

/// Pinch-to-zoom for terminal font size.
@MainActor
final class PinchProxy: NSObject {
    static let shared = PinchProxy()
    private var startSize: CGFloat = 13

    @objc func handle(_ gesture: UIPinchGestureRecognizer) {
        guard let view = gesture.view as? TerminalView else { return }
        switch gesture.state {
        case .began:
            startSize = view.font.pointSize
        case .changed:
            let size = min(max(startSize * gesture.scale, 8), 32).rounded()
            if size != view.font.pointSize {
                view.font = UIFont.monospacedSystemFont(ofSize: size, weight: .regular)
            }
        default:
            break
        }
    }
}
