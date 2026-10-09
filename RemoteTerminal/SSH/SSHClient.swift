import Foundation
import NIOConcurrencyHelpers
import NIOCore
import NIOSSH
import NIOTransportServices

// MARK: - Errors

enum SSHClientError: LocalizedError {
    case authenticationFailed(offered: [String], serverAccepts: [String])
    case hostKeyRejected(String)
    case connectionClosed
    case invalidChannelType

    var errorDescription: String? {
        switch self {
        case let .authenticationFailed(offered, accepts):
            let tried = offered.isEmpty ? "no credentials configured" : "tried " + offered.joined(separator: ", ")
            return "Permission denied (\(tried)). Server accepts: \(accepts.joined(separator: ", "))."
        case .hostKeyRejected(let reason): return "Host key rejected: \(reason)"
        case .connectionClosed: return "Connection closed by remote host."
        case .invalidChannelType: return "Server opened an unexpected channel type."
        }
    }
}

// MARK: - Host key validation

enum HostKeyDecision: Sendable {
    case trust
    case reject(String)
}

typealias HostKeyHandler = @Sendable (NIOSSHPublicKey) async -> HostKeyDecision

/// Bridges NIO's host-key callback to an async decision (which may involve prompting the user).
final class HostKeyValidator: NIOSSHClientServerAuthenticationDelegate, Sendable {
    private let handler: HostKeyHandler

    init(handler: @escaping HostKeyHandler) { self.handler = handler }

    func validateHostKey(hostKey: NIOSSHPublicKey, validationCompletePromise: EventLoopPromise<Void>) {
        let handler = self.handler
        Task {
            switch await handler(hostKey) {
            case .trust: validationCompletePromise.succeed(())
            case .reject(let reason): validationCompletePromise.fail(SSHClientError.hostKeyRejected(reason))
            }
        }
    }
}

typealias PasswordPromptHandler = @Sendable (_ username: String, _ isRetry: Bool) async -> String?

// MARK: - User authentication

/// Offers the private key first (if any), then the saved password (if any), and interactively prompts if needed.
final class ClientAuthDelegate: NIOSSHClientUserAuthenticationDelegate, Sendable {
    private struct State {
        var triedKey = false
        var triedSavedPassword = false
        var promptAttempts = 0
        var offered: [String] = []
    }

    private let username: String
    private let privateKey: NIOSSHPrivateKey?
    private let savedPassword: String?
    private let passwordPromptHandler: PasswordPromptHandler?
    private let state = NIOLockedValueBox(State())

    init(
        username: String,
        privateKey: NIOSSHPrivateKey?,
        password: String?,
        passwordPromptHandler: PasswordPromptHandler? = nil
    ) {
        self.username = username
        self.privateKey = privateKey
        self.savedPassword = password
        self.passwordPromptHandler = passwordPromptHandler
    }

    func nextAuthenticationType(
        availableMethods: NIOSSHAvailableUserAuthenticationMethods,
        nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>
    ) {
        // Step 1: Offer private key if available and not yet tried
        let shouldOfferKey: Bool = state.withLockedValue { s in
            if privateKey != nil, !s.triedKey, availableMethods.contains(.publicKey) {
                s.triedKey = true
                s.offered.append("publickey")
                return true
            }
            return false
        }
        if shouldOfferKey, let key = privateKey {
            nextChallengePromise.succeed(
                NIOSSHUserAuthenticationOffer(
                    username: username,
                    serviceName: "",
                    offer: .privateKey(.init(privateKey: key))
                )
            )
            return
        }

        // Step 2: Offer saved password if available and not yet tried
        let shouldOfferSavedPassword: Bool = state.withLockedValue { s in
            if savedPassword != nil, !s.triedSavedPassword, availableMethods.contains(.password) {
                s.triedSavedPassword = true
                if !s.offered.contains("password") { s.offered.append("password") }
                return true
            }
            return false
        }
        if shouldOfferSavedPassword, let password = savedPassword {
            nextChallengePromise.succeed(
                NIOSSHUserAuthenticationOffer(
                    username: username,
                    serviceName: "",
                    offer: .password(.init(password: password))
                )
            )
            return
        }

        // Step 3: If password authentication is supported and an interactive prompt handler is provided,
        // prompt the user (allow up to 3 attempts)
        let (canPrompt, isRetry, offered): (Bool, Bool, [String]) = state.withLockedValue { s in
            if availableMethods.contains(.password), passwordPromptHandler != nil, s.promptAttempts < 3 {
                let isRetry = s.triedSavedPassword || s.promptAttempts > 0
                s.promptAttempts += 1
                if !s.offered.contains("password") { s.offered.append("password") }
                return (true, isRetry, s.offered)
            }
            return (false, false, s.offered)
        }

        if canPrompt, let handler = passwordPromptHandler {
            let user = username
            Task {
                if let enteredPassword = await handler(user, isRetry) {
                    nextChallengePromise.succeed(
                        NIOSSHUserAuthenticationOffer(
                            username: user,
                            serviceName: "",
                            offer: .password(.init(password: enteredPassword))
                        )
                    )
                } else {
                    var accepts: [String] = []
                    if availableMethods.contains(.publicKey) { accepts.append("publickey") }
                    if availableMethods.contains(.password) { accepts.append("password") }
                    if availableMethods.contains(.hostBased) { accepts.append("hostbased") }
                    nextChallengePromise.fail(SSHClientError.authenticationFailed(offered: offered, serverAccepts: accepts))
                }
            }
            return
        }

        // Step 4: No further methods available
        var accepts: [String] = []
        if availableMethods.contains(.publicKey) { accepts.append("publickey") }
        if availableMethods.contains(.password) { accepts.append("password") }
        if availableMethods.contains(.hostBased) { accepts.append("hostbased") }
        nextChallengePromise.fail(SSHClientError.authenticationFailed(offered: offered, serverAccepts: accepts))
    }
}

// MARK: - Connection readiness

/// Completes `ready` once user auth succeeds, or fails it on the first error / disconnect.
private final class ConnectionReadyHandler: ChannelInboundHandler {
    typealias InboundIn = Any

    private let ready: EventLoopPromise<Void>
    private var completed = false

    init(ready: EventLoopPromise<Void>) { self.ready = ready }

    private func complete(_ result: Result<Void, Error>) {
        guard !completed else { return }
        completed = true
        ready.completeWith(result)
    }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        if event is UserAuthSuccessEvent { complete(.success(())) }
        context.fireUserInboundEventTriggered(event)
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        complete(.failure(error))
        context.close(promise: nil)
    }

    func channelInactive(context: ChannelHandlerContext) {
        complete(.failure(SSHClientError.connectionClosed))
        context.fireChannelInactive()
    }
}

// MARK: - Client

/// An authenticated SSH connection. Open one or more shells on it with `openShell`.
final class SSHClient: Sendable {
    /// Network.framework-backed event loop (preferred on iOS over BSD sockets).
    static let group = NIOTSEventLoopGroup(loopCount: 1, defaultQoS: .userInitiated)

    let channel: Channel

    private init(channel: Channel) { self.channel = channel }

    static func connect(
        host: String,
        port: Int,
        username: String,
        privateKey: NIOSSHPrivateKey?,
        password: String?,
        passwordPromptHandler: PasswordPromptHandler? = nil,
        connectTimeout: TimeAmount = .seconds(15),
        hostKeyHandler: @escaping HostKeyHandler
    ) async throws -> SSHClient {
        let auth = ClientAuthDelegate(
            username: username,
            privateKey: privateKey,
            password: password,
            passwordPromptHandler: passwordPromptHandler
        )
        let validator = HostKeyValidator(handler: hostKeyHandler)
        let loop = group.next()
        let ready = loop.makePromise(of: Void.self)

        let bootstrap = NIOTSConnectionBootstrap(group: loop)
            .connectTimeout(connectTimeout)
            .channelOption(NIOTSChannelOptions.waitForActivity, value: false)
            .channelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    let ssh = NIOSSHHandler(
                        role: .client(.init(userAuthDelegate: auth, serverAuthDelegate: validator)),
                        allocator: channel.allocator,
                        inboundChildChannelInitializer: nil)
                    try channel.pipeline.syncOperations.addHandlers(ssh, ConnectionReadyHandler(ready: ready))
                }
            }

        let channel: Channel
        do {
            channel = try await bootstrap.connect(host: host, port: port).get()
        } catch {
            ready.fail(error) // avoid leaking the promise
            throw error
        }

        do {
            try await ready.futureResult.get()
        } catch {
            channel.close(promise: nil)
            throw error
        }
        return SSHClient(channel: channel)
    }

    /// Opens a session channel with an interactive PTY shell.
    func openShell(
        term: String = "xterm-256color",
        cols: Int,
        rows: Int,
        onOutput: @escaping @Sendable ([UInt8]) -> Void,
        onClose: @escaping @Sendable (Int?) -> Void
    ) async throws -> SSHShell {
        let parent = channel
        let child: Channel = try await parent.eventLoop.flatSubmit {
            let promise = parent.eventLoop.makePromise(of: Channel.self)
            do {
                let ssh = try parent.pipeline.syncOperations.handler(type: NIOSSHHandler.self)
                ssh.createChannel(promise, channelType: .session) { child, type in
                    guard type == .session else {
                        return child.eventLoop.makeFailedFuture(SSHClientError.invalidChannelType)
                    }
                    return child.eventLoop.makeCompletedFuture {
                        try child.pipeline.syncOperations.addHandler(ShellChannelHandler(onOutput: onOutput, onClose: onClose))
                    }
                }
            } catch {
                promise.fail(error)
            }
            return promise.futureResult
        }.get()

        let pty = SSHChannelRequestEvent.PseudoTerminalRequest(
            wantReply: true, term: term,
            terminalCharacterWidth: cols, terminalRowHeight: rows,
            terminalPixelWidth: 0, terminalPixelHeight: 0,
            terminalModes: SSHTerminalModes([:]))
        try await child.triggerUserOutboundEvent(pty).get()
        try await child.triggerUserOutboundEvent(SSHChannelRequestEvent.ShellRequest(wantReply: true)).get()
        return SSHShell(channel: child)
    }

    func close() {
        channel.close(promise: nil)
    }
}

// MARK: - Shell

/// Handle to an interactive shell channel.
final class SSHShell: Sendable {
    let channel: Channel

    init(channel: Channel) { self.channel = channel }

    func write(_ bytes: some Sequence<UInt8>) {
        var buffer = channel.allocator.buffer(capacity: 64)
        buffer.writeBytes(bytes)
        channel.writeAndFlush(buffer, promise: nil)
    }

    func resize(cols: Int, rows: Int) {
        let event = SSHChannelRequestEvent.WindowChangeRequest(
            terminalCharacterWidth: cols, terminalRowHeight: rows,
            terminalPixelWidth: 0, terminalPixelHeight: 0)
        channel.triggerUserOutboundEvent(event, promise: nil)
    }

    func close() {
        channel.close(promise: nil)
    }
}

/// Converts between raw bytes and `SSHChannelData`, and reports exit status / closure.
private final class ShellChannelHandler: ChannelDuplexHandler {
    typealias InboundIn = SSHChannelData
    typealias OutboundIn = ByteBuffer
    typealias OutboundOut = SSHChannelData

    private let onOutput: @Sendable ([UInt8]) -> Void
    private let onClose: @Sendable (Int?) -> Void
    private var exitStatus: Int?

    init(onOutput: @escaping @Sendable ([UInt8]) -> Void, onClose: @escaping @Sendable (Int?) -> Void) {
        self.onOutput = onOutput
        self.onClose = onClose
    }

    func handlerAdded(context: ChannelHandlerContext) {
        let loopBoundContext = NIOLoopBound(context, eventLoop: context.eventLoop)
        context.channel.setOption(ChannelOptions.allowRemoteHalfClosure, value: true).whenFailure { error in
            loopBoundContext.value.fireErrorCaught(error)
        }
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let message = unwrapInboundIn(data)
        guard case .byteBuffer(var buffer) = message.data,
              let bytes = buffer.readBytes(length: buffer.readableBytes), !bytes.isEmpty
        else { return }
        // stdout and stderr both go to the terminal.
        onOutput(bytes)
    }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        switch event {
        case let status as SSHChannelRequestEvent.ExitStatus:
            exitStatus = status.exitStatus
        case ChannelEvent.inputClosed:
            context.close(promise: nil)
        default:
            context.fireUserInboundEventTriggered(event)
        }
    }

    func channelInactive(context: ChannelHandlerContext) {
        onClose(exitStatus)
        context.fireChannelInactive()
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        context.close(promise: nil)
    }

    func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        let buffer = unwrapOutboundIn(data)
        context.write(wrapOutboundOut(SSHChannelData(type: .channel, data: .byteBuffer(buffer))), promise: promise)
    }
}
