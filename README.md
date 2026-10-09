# RemoteTerminal for iOS

RemoteTerminal is a native iOS SSH client built using SwiftUI, SwiftData, `swift-nio-ssh`, and `SwiftTerm`. It allows you to securely manage hosts, generate SSH keys (including Secure Enclave hardware keys), and connect to remote servers or your Mac directly from your iPhone.

## Features
* **Modern UI:** Built entirely in SwiftUI with a clean, tabbed interface for managing multiple active sessions simultaneously.
* **Terminal Emulation:** Uses `SwiftTerm` for robust VT100/xterm emulation, supporting complex terminal apps like `vim`, `htop`, and `tmux`.
* **Hardware Security:** Generate Ed25519 or ECDSA keys directly inside your iPhone's Secure Enclave, making them physically impossible to extract.
* **Smart Authentication:** Supports a seamless fallback auth model: tries SSH keys first, then saved Keychain passwords, and finally an interactive prompt.
* **Trust On First Use (TOFU):** Automatically prompts you when connecting to new servers or when a server's fingerprint changes.

---

## 🛠 Building the App

This project uses [XcodeGen](https://github.com/yonaskolb/XcodeGen) to define the project structure. The `.xcodeproj` is ignored in Git to prevent merge conflicts.

### Prerequisites
1. Install [XcodeGen](https://github.com/yonaskolb/XcodeGen) (e.g., via Homebrew: `brew install xcodegen`).
2. Clone the repository.

### Build Steps
1. Open your terminal and navigate to the project folder.
2. Run the following command to generate the Xcode project:
   ```bash
   xcodegen generate
   ```
3. Open the newly created `RemoteTerminal.xcodeproj`.
4. Select your Development Team in the **Signing & Capabilities** tab (if deploying to a physical iPhone).
5. Hit **Play**!

---

## 📖 How to Use the App

RemoteTerminal supports two primary ways to authenticate with your remote servers: **Password Authentication** and **SSH Key Authentication**.

### Mode 1: Using Password Authentication (Quickest)
If your server (or Mac) allows standard passwords, you can connect instantly without any prior setup.

1. Open the app and go to the **Hosts** tab.
2. Tap the **+** button in the top right to add a new host.
3. Fill in the details:
   * **Host:** The IP address of your server (e.g., `192.168.1.5`).
   * **Port:** Usually `22`.
   * **Username:** The username on your server.
4. Under **Authentication Method**, select **Password**.
5. Leave the password field blank if you want it to prompt you, or type it in to save it securely to your iPhone's Keychain.
6. Tap **Save**, then tap your new host and hit **Connect**.
7. If you left the password blank, a secure UI prompt will pop up asking you to type it before dropping you into the terminal!

### Mode 2: Using SSH Key Authentication (Most Secure)
Using an SSH Key is highly recommended, especially if you generate it using your iPhone's Secure Enclave.

**Step A: Generate a Key on your iPhone**
1. Go to the **Keys** tab in the app.
2. Tap the **+** button to create a new key.
3. Name it (e.g., "iPhone Key"), select the **Ed25519** type, and toggle **Use Secure Enclave** for maximum security.
4. Tap **Save**.
5. Tap your newly created key in the list and select **Copy Public Key**.

**Step B: Put the Public Key on your Server**
1. SSH into your server (using your Mac or the app's Password mode).
2. Open your authorized keys file: `nano ~/.ssh/authorized_keys`
3. Paste the Public Key you copied from the app onto a new line.
4. Save the file.

**Step C: Connect!**
1. Go to the **Hosts** tab and create a new host (or edit an existing one).
2. Enter your server's IP and Username.
3. Under **Authentication Method**, select **SSH Key**.
4. A new dropdown will appear—select the "iPhone Key" you generated.
5. Tap **Save** and then hit **Connect**. The app will securely authenticate using the cryptographic key—no passwords required!

---

## Technical Stack
* UI Framework: `SwiftUI`
* Database: `SwiftData` & iOS `Keychain`
* SSH Transport: `swift-nio-ssh` (Apple)
* Terminal Emulator: `SwiftTerm`
* Project Generation: `XcodeGen`

## License
MIT License. See LICENSE for more information.
