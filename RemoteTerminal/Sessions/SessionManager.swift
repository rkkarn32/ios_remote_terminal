import Foundation
import Observation
import SwiftData

enum RootTab: Hashable {
    case hosts, sessions, keys
}

/// Owns all open sessions and the current tab selection.
@MainActor
@Observable
final class SessionManager {
    var sessions: [TerminalSession] = []
    var activeID: UUID?
    var selectedTab: RootTab = .hosts

    @ObservationIgnored let container: ModelContainer

    init(container: ModelContainer) {
        self.container = container
    }

    var activeSession: TerminalSession? {
        sessions.first { $0.id == activeID } ?? sessions.last
    }

    func open(_ host: SavedHost) {
        let session = TerminalSession(target: ConnectionTarget(host), container: container)
        sessions.append(session)
        activeID = session.id
        selectedTab = .sessions
        session.start()
    }

    func close(_ session: TerminalSession) {
        session.disconnect()
        let index = sessions.firstIndex { $0.id == session.id }
        sessions.removeAll { $0.id == session.id }
        if activeID == session.id {
            if let index, !sessions.isEmpty {
                activeID = sessions[min(index, sessions.count - 1)].id
            } else {
                activeID = nil
            }
        }
    }

    func activate(_ session: TerminalSession) {
        activeID = session.id
    }
}
