import SwiftData
import SwiftUI

enum AuthMethod: String, CaseIterable, Identifiable {
    case password = "Password"
    case sshKey = "SSH Key"
    case both = "Key + Password"

    var id: String { rawValue }
}

struct HostEditorView: View {
    let host: SavedHost?

    @Environment(\.dismiss) private var dismiss
    @Environment(\.modelContext) private var context
    @Query(sort: \SSHKeyRecord.createdAt) private var keys: [SSHKeyRecord]

    @State private var name = ""
    @State private var hostname = ""
    @State private var port = "22"
    @State private var username = ""
    @State private var authMethod: AuthMethod = .password
    @State private var keyID: UUID?
    @State private var savePassword = true
    @State private var password = ""
    @State private var passwordChanged = false
    @State private var errorMessage: String?

    private var isValid: Bool {
        !hostname.trimmingCharacters(in: .whitespaces).isEmpty
            && !username.trimmingCharacters(in: .whitespaces).isEmpty
            && (Int(port).map { (1...65535).contains($0) } ?? false)
    }

    var body: some View {
        NavigationStack {
            Form {
                Section("Server") {
                    TextField("Label (optional)", text: $name)
                    TextField("Hostname or IP", text: $hostname)
                        .keyboardType(.URL)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    TextField("Port", text: $port).keyboardType(.numberPad)
                }

                Section("User") {
                    TextField("Username", text: $username)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                }

                Section {
                    Picker("Method", selection: $authMethod) {
                        ForEach(AuthMethod.allCases) { method in
                            Text(method.rawValue).tag(method)
                        }
                    }
                    .pickerStyle(.segmented)

                    if authMethod == .sshKey || authMethod == .both {
                        if keys.isEmpty {
                            VStack(alignment: .leading, spacing: 4) {
                                Text("No SSH keys found.").font(.subheadline).foregroundStyle(.secondary)
                                Text("Generate or import a key in the Keys tab first.").font(.caption).foregroundStyle(.secondary)
                            }
                        } else {
                            Picker("SSH Key", selection: $keyID) {
                                ForEach(keys) { key in
                                    Text("\(key.name) (\(key.kind.displayName))").tag(UUID?.some(key.id))
                                }
                            }
                        }
                    }

                    if authMethod == .password || authMethod == .both {
                        SecureField(host?.hasSavedPassword == true && !passwordChanged ? "•••••••• (saved in Keychain)" : "Password (optional)", text: $password)
                            .onChange(of: password) { passwordChanged = true }

                        Toggle("Save Password in Keychain", isOn: $savePassword)
                    }
                } header: {
                    Text("Authentication")
                } footer: {
                    Text("Passwords are saved only in the device Keychain. If you don't enter or save a password here, you will be prompted when connecting.")
                }

                if let errorMessage {
                    Section { Text(errorMessage).foregroundStyle(.red) }
                }
            }
            .navigationTitle(host == nil ? "New Host" : "Edit Host")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) { Button("Save", action: save).disabled(!isValid) }
            }
            .onAppear(perform: load)
        }
    }

    private func load() {
        if let host {
            name = host.name
            hostname = host.hostname
            port = String(host.port)
            username = host.username
            keyID = host.keyID
            savePassword = host.hasSavedPassword

            if host.keyID != nil && host.hasSavedPassword {
                authMethod = .both
            } else if host.keyID != nil {
                authMethod = .sshKey
            } else {
                authMethod = .password
            }
        } else {
            // New host
            if keys.isEmpty {
                authMethod = .password
                keyID = nil
            } else {
                authMethod = .sshKey
                keyID = keys.last?.id
            }
            savePassword = true
        }
    }

    private func save() {
        let target = host ?? SavedHost(name: "", hostname: "", username: "")
        target.name = name.trimmingCharacters(in: .whitespaces)
        target.hostname = hostname.trimmingCharacters(in: .whitespaces)
        target.port = Int(port) ?? 22
        target.username = username.trimmingCharacters(in: .whitespaces)

        switch authMethod {
        case .password:
            target.keyID = nil
        case .sshKey:
            target.keyID = keyID ?? keys.first?.id
        case .both:
            target.keyID = keyID ?? keys.first?.id
        }

        do {
            if authMethod == .password || authMethod == .both {
                if savePassword {
                    if passwordChanged && !password.isEmpty {
                        try KeychainStore.shared.setString(password, account: target.passwordKeychainAccount)
                        target.hasSavedPassword = true
                    } else if host == nil && !password.isEmpty {
                        try KeychainStore.shared.setString(password, account: target.passwordKeychainAccount)
                        target.hasSavedPassword = true
                    }
                } else {
                    try KeychainStore.shared.delete(target.passwordKeychainAccount)
                    target.hasSavedPassword = false
                }
            } else {
                try KeychainStore.shared.delete(target.passwordKeychainAccount)
                target.hasSavedPassword = false
            }

            if host == nil { context.insert(target) }
            try context.save()
            dismiss()
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}
