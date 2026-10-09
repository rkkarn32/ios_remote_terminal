import SwiftData
import SwiftUI

struct KeyListView: View {
    @Environment(\.modelContext) private var context
    @Query(sort: \SSHKeyRecord.createdAt) private var keys: [SSHKeyRecord]
    @State private var isShowingDetail: SSHKeyRecord?
    @State private var isImporting = false
    @State private var isGenerating = false

    var body: some View {
        NavigationStack {
            Group {
                if keys.isEmpty {
                    ContentUnavailableView {
                        Label("No Keys", systemImage: "key")
                    } description: {
                        Text("Generate an Ed25519 key or import an existing private key to connect without passwords.")
                    } actions: {
                        Button("Generate Key") { isGenerating = true }.buttonStyle(.borderedProminent)
                        Button("Import Key") { isImporting = true }.padding(.top)
                    }
                } else {
                    List {
                        ForEach(keys) { key in
                            Button { isShowingDetail = key } label: { KeyRow(key: key) }
                                .swipeActions(edge: .trailing) {
                                    Button(role: .destructive) { try? KeyManager.delete(key, context: context) } label: { Label("Delete", systemImage: "trash") }
                                }
                                .contextMenu {
                                    Button(role: .destructive) { try? KeyManager.delete(key, context: context) } label: { Label("Delete", systemImage: "trash") }
                                }
                        }
                    }
                }
            }
            .navigationTitle("SSH Keys")
            .toolbar {
                ToolbarItem(placement: .primaryAction) {
                    Menu {
                        Button("Generate New Key", systemImage: "sparkles") { isGenerating = true }
                        Button("Import Private Key", systemImage: "square.and.arrow.down") { isImporting = true }
                    } label: {
                        Image(systemName: "plus")
                    }
                }
            }
            .sheet(item: $isShowingDetail) { KeyDetailView(keyRecord: $0) }
            .sheet(isPresented: $isGenerating) { KeyGenerateView() }
            .sheet(isPresented: $isImporting) { KeyImportView() }
        }
    }
}

private struct KeyRow: View {
    let key: SSHKeyRecord

    var body: some View {
        HStack {
            Image(systemName: "key.fill")
                .font(.title2)
                .foregroundStyle(.blue)
                .frame(width: 36)
            VStack(alignment: .leading, spacing: 2) {
                Text(key.name).font(.headline).foregroundStyle(.primary)
                Text(key.kind.displayName).font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
        }
        .padding(.vertical, 4)
    }
}

struct KeyDetailView: View {
    let keyRecord: SSHKeyRecord
    @Environment(\.dismiss) private var dismiss
    @State private var copied = false

    var body: some View {
        NavigationStack {
            List {
                Section("Information") {
                    LabeledContent("Name", value: keyRecord.name)
                    LabeledContent("Type", value: keyRecord.kind.displayName)
                    LabeledContent("Created", value: keyRecord.createdAt.formatted(date: .abbreviated, time: .shortened))
                }
                Section("Fingerprint (SHA256)") {
                    Text(keyRecord.fingerprint)
                        .font(.caption.monospaced())
                        .textSelection(.enabled)
                }
                Section("Public Key") {
                    Text(keyRecord.publicKeyOpenSSH)
                        .font(.caption.monospaced())
                        .textSelection(.enabled)

                    Button(action: copyPublicKey) {
                        Label(copied ? "Copied to Clipboard" : "Copy Public Key", systemImage: copied ? "checkmark" : "doc.on.doc")
                    }
                    ShareLink(item: keyRecord.publicKeyOpenSSH, preview: SharePreview(keyRecord.name)) {
                        Label("Share Public Key…", systemImage: "square.and.arrow.up")
                    }
                }
                Section {
                    EmptyView()
                } footer: {
                    Text("To use this key, copy it and paste it into the remote server's `~/.ssh/authorized_keys` file.")
                }
            }
            .navigationTitle("Key Details")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } }
            }
        }
    }

    private func copyPublicKey() {
        UIPasteboard.general.string = keyRecord.publicKeyOpenSSH
        withAnimation { copied = true }
        DispatchQueue.main.asyncAfter(deadline: .now() + 2) { withAnimation { copied = false } }
    }
}

struct KeyGenerateView: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(\.modelContext) private var context
    @State private var name = ""
    @State private var useSecureEnclave = false

    var body: some View {
        NavigationStack {
            Form {
                Section("Details") {
                    TextField("Key Name (e.g., iPhone)", text: $name)
                        .textInputAutocapitalization(.words)
                }
                if KeyManager.isSecureEnclaveAvailable {
                    Section {
                        Toggle("Use Secure Enclave", isOn: $useSecureEnclave)
                    } footer: {
                        Text("Secure Enclave keys (ECDSA P-256) are locked to this device's hardware and cannot be extracted.")
                    }
                }
            }
            .navigationTitle("Generate Key")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Generate", action: generate).disabled(name.trimmingCharacters(in: .whitespaces).isEmpty)
                }
            }
        }
    }

    private func generate() {
        let kind: SSHKeyKind = useSecureEnclave ? .secureEnclaveP256 : .ed25519
        try? KeyManager.generateAndSave(name: name.trimmingCharacters(in: .whitespaces), kind: kind, context: context)
        dismiss()
    }
}

struct KeyImportView: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(\.modelContext) private var context
    @State private var text = ""
    @State private var name = ""
    @State private var errorMessage: String?

    var body: some View {
        NavigationStack {
            Form {
                Section("Paste Private Key") {
                    TextEditor(text: $text)
                        .font(.caption.monospaced())
                        .frame(minHeight: 150)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                }
                Section("Label") {
                    TextField("Optional Name", text: $name)
                }
                if let errorMessage {
                    Section { Text(errorMessage).foregroundStyle(.red) }
                }
            }
            .navigationTitle("Import Key")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Import", action: importKey).disabled(text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }
            }
        }
    }

    private func importKey() {
        do {
            try KeyManager.importAndSave(text: text, name: name.trimmingCharacters(in: .whitespaces), context: context)
            dismiss()
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}
