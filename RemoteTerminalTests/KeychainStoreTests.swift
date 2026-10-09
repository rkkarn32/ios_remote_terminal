import XCTest
@testable import RemoteTerminal

final class KeychainStoreTests: XCTestCase {
    // Use a unique service name so we don't clobber real data during testing
    let store = KeychainStore(service: "con.sshapp.RemoteTerminal.Tests")

    override func setUp() {
        super.setUp()
        try? store.delete("test.account")
    }

    func testSetGetDelete() throws {
        let account = "test.account"
        let data = Data("secret".utf8)

        // Doesn't exist initially
        XCTAssertNil(try store.data(for: account))

        // Set
        try store.set(data, account: account)

        // Get
        XCTAssertEqual(try store.data(for: account), data)

        // Update
        let newData = Data("new_secret".utf8)
        try store.set(newData, account: account)
        XCTAssertEqual(try store.data(for: account), newData)

        // Delete
        try store.delete(account)
        XCTAssertNil(try store.data(for: account))

        // Delete non-existent succeeds
        try store.delete(account)
    }

    func testStringConvenience() throws {
        let account = "test.password"
        let pass = "hunter2"

        try store.setString(pass, account: account)
        XCTAssertEqual(try store.string(for: account), pass)

        try store.delete(account)
        XCTAssertNil(try store.string(for: account))
    }
}
