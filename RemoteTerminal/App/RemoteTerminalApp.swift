import SwiftData
import SwiftUI

@main
struct RemoteTerminalApp: App {
    let container: ModelContainer
    @State private var sessionManager: SessionManager

    init() {
        let container: ModelContainer
        do {
            container = try ModelContainer(for: SavedHost.self, SSHKeyRecord.self, KnownHost.self)
        } catch {
            fatalError("Failed to create the data store: \(error)")
        }
        self.container = container
        _sessionManager = State(initialValue: SessionManager(container: container))
    }

    var body: some Scene {
        WindowGroup {
            RootView()
                .environment(sessionManager)
                .preferredColorScheme(.dark)
                .tint(.green)
        }
        .modelContainer(container)
    }
}

struct RootView: View {
    @Environment(SessionManager.self) private var sessions

    var body: some View {
        @Bindable var sessions = sessions
        TabView(selection: $sessions.selectedTab) {
            HostListView()
                .tabItem { Label("Hosts", systemImage: "server.rack") }
                .tag(RootTab.hosts)
            SessionTabsView()
                .tabItem { Label("Sessions", systemImage: "terminal") }
                .badge(sessions.sessions.count)
                .tag(RootTab.sessions)
            KeyListView()
                .tabItem { Label("Keys", systemImage: "key") }
                .tag(RootTab.keys)
        }
    }
}
