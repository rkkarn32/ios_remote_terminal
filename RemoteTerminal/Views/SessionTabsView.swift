import SwiftUI

struct SessionTabsView: View {
    @Environment(SessionManager.self) private var sessions

    var body: some View {
        VStack(spacing: 0) {
            if sessions.sessions.isEmpty {
                ContentUnavailableView {
                    Label("No Active Sessions", systemImage: "terminal")
                } description: {
                    Text("Select a host from the Hosts tab to connect.")
                }
            } else {
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 8) {
                        ForEach(sessions.sessions) { session in
                            TabItem(session: session, isActive: session.id == sessions.activeID) {
                                sessions.activate(session)
                            } onClose: {
                                sessions.close(session)
                            }
                        }
                    }
                    .padding(.horizontal, 8)
                    .padding(.vertical, 6)
                }
                .background(Color(white: 0.15))

                Divider()

                if let active = sessions.activeSession {
                    TerminalHostView(session: active)
                        .id(active.id)
                }
            }
        }
    }
}

private struct TabItem: View {
    let session: TerminalSession
    let isActive: Bool
    let onSelect: () -> Void
    let onClose: () -> Void

    var body: some View {
        Button(action: onSelect) {
            HStack(spacing: 6) {
                Circle()
                    .fill(statusColor)
                    .frame(width: 8, height: 8)
                Text(session.title)
                    .font(.subheadline)
                    .lineLimit(1)
                    .foregroundStyle(isActive ? .primary : .secondary)
                Button(action: onClose) {
                    Image(systemName: "xmark")
                        .font(.system(size: 10, weight: .bold))
                        .foregroundStyle(.secondary)
                        .padding(4)
                }
                .buttonStyle(.plain)
            }
            .padding(.leading, 8)
            .padding(.trailing, 4)
            .padding(.vertical, 6)
            .background(isActive ? Color(white: 0.25) : Color(white: 0.1))
            .cornerRadius(8)
            .overlay(
                RoundedRectangle(cornerRadius: 8)
                    .strokeBorder(isActive ? Color.gray : Color.clear, lineWidth: 1)
            )
        }
        .buttonStyle(.plain)
    }

    private var statusColor: Color {
        switch session.state {
        case .connecting: .yellow
        case .awaitingHostKeyTrust: .orange
        case .connected: .green
        case .disconnected: .red
        }
    }
}

/// Wraps the UIKit terminal view and overlays trust prompts and disconnect banners.
private struct TerminalHostView: View {
    let session: TerminalSession

    var body: some View {
        ZStack(alignment: .top) {
            TerminalRepresentable(terminalView: session.terminalView)
                .ignoresSafeArea(.keyboard)

            if let prompt = session.hostKeyPrompt {
                HostKeyPromptView(prompt: prompt) { session.resolveHostKeyPrompt(trust: $0) }
                    .transition(.move(edge: .top).combined(with: .opacity))
                    .zIndex(2)
            } else if let prompt = session.passwordPrompt {
                PasswordPromptView(prompt: prompt) { password, save in
                    session.resolvePasswordPrompt(password: password, saveToKeychain: save)
                }
                .transition(.move(edge: .top).combined(with: .opacity))
                .zIndex(2)
            } else if case .disconnected(let reason) = session.state {
                DisconnectedBanner(reason: reason) { session.reconnect() }
                    .transition(.move(edge: .top).combined(with: .opacity))
                    .zIndex(1)
            }
        }
        .animation(.spring(response: 0.3, dampingFraction: 0.8), value: session.state)
    }
}

private struct TerminalRepresentable: UIViewRepresentable {
    let terminalView: UIView

    func makeUIView(context: Context) -> UIView { terminalView }
    func updateUIView(_ uiView: UIView, context: Context) {}
}

private struct HostKeyPromptView: View {
    let prompt: HostKeyPrompt
    let onResolve: (Bool) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundStyle(isWarning ? .red : .yellow)
                Text(isWarning ? "Host Key Changed!" : "Unknown Host Key")
                    .font(.headline)
            }

            if case .changed(let previous) = prompt.kind {
                Text("The host key for **\(prompt.hostPort)** has changed. This could be a man-in-the-middle attack, or the server was reinstalled.")
                    .font(.subheadline)
                Text("Previous: \(previous)")
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
            } else {
                Text("The authenticity of **\(prompt.hostPort)** can't be established.")
                    .font(.subheadline)
            }

            VStack(alignment: .leading, spacing: 4) {
                Text("Type: \(prompt.keyType)").font(.caption).foregroundStyle(.secondary)
                Text("Fingerprint: \(prompt.fingerprint)").font(.caption.monospaced())
            }

            HStack {
                Button(role: .cancel) { onResolve(false) } label: {
                    Text("Cancel").frame(maxWidth: .infinity)
                }
                .buttonStyle(.bordered)

                Button(role: isWarning ? .destructive : .none) { onResolve(true) } label: {
                    Text(isWarning ? "Trust Anyway" : "Trust & Connect").frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
            }
            .padding(.top, 4)
        }
        .padding()
        .background(.regularMaterial)
        .cornerRadius(12)
        .shadow(radius: 10)
        .padding()
    }

    private var isWarning: Bool {
        if case .changed = prompt.kind { return true }
        return false
    }
}

private struct DisconnectedBanner: View {
    let reason: String?
    let onReconnect: () -> Void

    var body: some View {
        HStack {
            Image(systemName: "xmark.octagon.fill")
                .foregroundStyle(.red)
            Text(reason ?? "Disconnected")
                .font(.subheadline)
                .lineLimit(2)
            Spacer()
            Button("Reconnect", action: onReconnect)
                .buttonStyle(.bordered)
                .controlSize(.small)
        }
        .padding(12)
        .background(.regularMaterial)
        .cornerRadius(8)
        .shadow(radius: 4)
        .padding()
    }
}

private struct PasswordPromptView: View {
    let prompt: PasswordPrompt
    let onResolve: (String?, Bool) -> Void

    @State private var password = ""
    @State private var saveToKeychain = true

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Image(systemName: "lock.shield.fill")
                    .foregroundStyle(.blue)
                Text("SSH Password Required")
                    .font(.headline)
            }

            if prompt.isRetry {
                Text("Password was incorrect. Please try again:")
                    .font(.subheadline)
                    .foregroundStyle(.red)
            } else {
                Text("Enter password for **\(prompt.username)@\(prompt.hostname)**:")
                    .font(.subheadline)
            }

            SecureField("Password", text: $password)
                .textFieldStyle(.roundedBorder)

            Toggle("Save password in Keychain", isOn: $saveToKeychain)
                .font(.subheadline)

            HStack {
                Button(role: .cancel) {
                    onResolve(nil, false)
                } label: {
                    Text("Cancel").frame(maxWidth: .infinity)
                }
                .buttonStyle(.bordered)

                Button {
                    onResolve(password, saveToKeychain)
                } label: {
                    Text("Connect").frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .disabled(password.isEmpty)
            }
            .padding(.top, 4)
        }
        .padding()
        .background(.regularMaterial)
        .cornerRadius(12)
        .shadow(radius: 10)
        .padding()
    }
}
