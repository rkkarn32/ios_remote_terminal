import NIOConcurrencyHelpers
import NIOSSH
import XCTest
@testable import RemoteTerminal

final class SSHIntegrationTests: XCTestCase {
    func testConnectionAndShell() async throws {
        guard let host = ProcessInfo.processInfo.environment["RT_SSH_TEST_HOST"],
              let user = ProcessInfo.processInfo.environment["RT_SSH_TEST_USER"],
              let keyString = ProcessInfo.processInfo.environment["RT_SSH_TEST_KEY"]
        else {
            throw XCTSkip("Skipping integration test: RT_SSH_TEST_HOST, RT_SSH_TEST_USER, or RT_SSH_TEST_KEY not set")
        }

        let key = try OpenSSHKeyCodec.parsePrivateKey(keyString).privateKey

        let client = try await SSHClient.connect(
            host: host,
            port: 22,
            username: user,
            privateKey: key,
            password: nil,
            hostKeyHandler: { _ in .trust } // Trust all for test
        )

        let outputExpectation = expectation(description: "Received output")
        let closeExpectation = expectation(description: "Shell closed")

        let receivedOutput = NIOLockedValueBox("")

        let shell = try await client.openShell(
            cols: 80,
            rows: 24,
            onOutput: { bytes in
                if let str = String(bytes: bytes, encoding: .utf8) {
                    receivedOutput.withLockedValue {
                        $0 += str
                        if $0.contains("rt-test-success") {
                            outputExpectation.fulfill()
                        }
                    }
                }
            },
            onClose: { status in
                closeExpectation.fulfill()
            }
        )

        // Send a command. The PTY will echo it back.
        shell.write(Array("echo rt-test-success\n".utf8))

        await fulfillment(of: [outputExpectation], timeout: 5.0)

        // Exit the shell gracefully
        shell.write(Array("exit\n".utf8))

        await fulfillment(of: [closeExpectation], timeout: 5.0)

        client.close()
    }
}
