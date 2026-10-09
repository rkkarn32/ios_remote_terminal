import SwiftData
import SwiftUI

struct HostListView: View {
    @Environment(SessionManager.self) private var sessions
    @Environment(\.modelContext) private var context
    @Query(sort: \SavedHost.name) private var hosts: [SavedHost]
    @State private var editing: SavedHost?
    @State private var isAdding = false
    @State private var search = ""

    private var filtered: [SavedHost] {
        guard !search.isEmpty else { return hosts }
        return hosts.filter {
            $0.displayName.localizedCaseInsensitiveContains(search)
                || $0.hostname.localizedCaseInsensitiveContains(search)
                || $0.username.localizedCaseInsensitiveContains(search)
        }
    }

    var body: some View {
        NavigationStack {
            Group {
                if hosts.isEmpty {
                    ContentUnavailableView {
                        Label("No Hosts", systemImage: "server.rack")
                    } description: {
                        Text("Add a Mac or Windows PC running an SSH server.")
                    } actions: {
                        Button("Add Host") { isAdding = true }.buttonStyle(.borderedProminent)
                    }
                } else {
                    List {
                        ForEach(filtered) { host in
                            Button { sessions.open(host) } label: { HostRow(host: host) }
                                .swipeActions(edge: .trailing) {
                                    Button(role: .destructive) { delete(host) } label: { Label("Delete", systemImage: "trash") }
                                    Button { editing = host } label: { Label("Edit", systemImage: "pencil") }.tint(.orange)
                                }
                                .contextMenu {
                                    Button { sessions.open(host) } label: { Label("Connect", systemImage: "play") }
                                    Button { editing = host } label: { Label("Edit", systemImage: "pencil") }
                                    Button(role: .destructive) { delete(host) } label: { Label("Delete", systemImage: "trash") }
                                }
                        }
                    }
                    .searchable(text: $search)
                }
            }
            .navigationTitle("Hosts")
            .toolbar {
                ToolbarItem(placement: .primaryAction) {
                    Button { isAdding = true } label: { Image(systemName: "plus") }
                        .accessibilityLabel("Add Host")
                }
            }
            .sheet(isPresented: $isAdding) { HostEditorView(host: nil) }
            .sheet(item: $editing) { HostEditorView(host: $0) }
        }
    }

    private func delete(_ host: SavedHost) {
        try? KeychainStore.shared.delete(host.passwordKeychainAccount)
        context.delete(host)
        try? context.save()
    }
}

private struct HostRow: View {
    let host: SavedHost

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: "desktopcomputer")
                .font(.title2)
                .foregroundStyle(.green)
                .frame(width: 36)
            VStack(alignment: .leading, spacing: 2) {
                Text(host.displayName).font(.headline).foregroundStyle(.primary)
                Text(host.addressDescription).font(.caption.monospaced()).foregroundStyle(.secondary)
            }
            Spacer()
            if host.keyID != nil { Image(systemName: "key.fill").foregroundStyle(.secondary).font(.caption) }
            if host.hasSavedPassword { Image(systemName: "lock.fill").foregroundStyle(.secondary).font(.caption) }
        }
        .padding(.vertical, 4)
    }
}
