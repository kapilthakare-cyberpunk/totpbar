import Cocoa
import CryptoKit
import UserNotifications
import Security
import AVFoundation

// MARK: - Model

struct Account {
    let issuer: String
    let name: String
    let secret: Data
    let digits: Int
    let period: Int
    let algo: String

    var title: String {
        if issuer.isEmpty { return name }
        if name.isEmpty { return issuer }
        return "\(issuer) (\(name))"
    }
    var key: String { "\(issuer):\(name)".lowercased() }
    var uriString: String {
        let secBase32 = secret.base32EncodedString()
        return "otpauth://totp/\(issuer):\(name)?secret=\(secBase32)&issuer=\(issuer)&digits=\(digits)&period=\(period)&algorithm=\(algo)"
    }
}

// MARK: - Base32 Extension

extension Data {
    func base32EncodedString() -> String {
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
        var bits = 0
        var value = 0
        var output = ""
        for byte in self {
            value = (value << 8) | Int(byte)
            bits += 8
            while bits >= 5 {
                bits -= 5
                let idx = (value >> bits) & 0x1F
                output.append(alphabet[idx])
            }
        }
        if bits > 0 {
            let idx = (value << (5 - bits)) & 0x1F
            output.append(alphabet[idx])
        }
        return output
    }
}

func base32Decode(_ s: String) -> Data? {
    let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
    var bits = 0
    var value = 0
    var out = [UInt8]()
    for c in s.uppercased() where c != "=" && c != " " && c != "-" {
        guard let idx = alphabet.firstIndex(of: c) else { return nil }
        value = (value << 5) | idx
        bits += 5
        if bits >= 8 {
            out.append(UInt8((value >> (bits - 8)) & 0xFF))
            bits -= 8
            value &= (1 << bits) - 1
        }
    }
    return Data(out)
}

func totp(_ a: Account, at date: Date = Date()) -> String {
    let counter = UInt64(date.timeIntervalSince1970) / UInt64(a.period)
    let msg = withUnsafeBytes(of: counter.bigEndian) { Data($0) }
    let key = SymmetricKey(data: a.secret)
    let mac: [UInt8]
    switch a.algo {
    case "SHA256": mac = Array(HMAC<SHA256>.authenticationCode(for: msg, using: key))
    case "SHA512": mac = Array(HMAC<SHA512>.authenticationCode(for: msg, using: key))
    default: mac = Array(HMAC<Insecure.SHA1>.authenticationCode(for: msg, using: key))
    }
    let off = Int(mac[mac.count - 1] & 0x0f)
    let bin = (UInt32(mac[off] & 0x7f) << 24)
        | (UInt32(mac[off + 1]) << 16)
        | (UInt32(mac[off + 2]) << 8)
        | UInt32(mac[off + 3])
    var mod: UInt32 = 1
    for _ in 0..<min(max(a.digits, 1), 9) { mod *= 10 }
    let code = String(bin % mod)
    return String(repeating: "0", count: max(0, a.digits - code.count)) + code
}

func parse(_ line: String) -> Account? {
    guard let c = URLComponents(string: line),
          c.scheme == "otpauth", c.host == "totp" else { return nil }
    var q: [String: String] = [:]
    for item in c.queryItems ?? [] {
        if let value = item.value { q[item.name.lowercased()] = value }
    }
    guard let sec = q["secret"], !sec.isEmpty, let secret = base32Decode(sec) else { return nil }
    var label = c.path
    if label.hasPrefix("/") { label.removeFirst() }
    var issuer = q["issuer"] ?? ""
    var name = label
    if let r = label.firstIndex(of: ":") {
        let lead = String(label[..<r]).trimmingCharacters(in: .whitespaces)
        name = String(label[label.index(after: r)...]).trimmingCharacters(in: .whitespaces)
        if issuer.isEmpty { issuer = lead }
    }
    let digits = min(max(Int(q["digits"] ?? "") ?? 6, 6), 8)
    let period = max(1, Int(q["period"] ?? "") ?? 30)
    let requestedAlgo = (q["algorithm"] ?? "SHA1").uppercased()
    let algo = ["SHA1", "SHA256", "SHA512"].contains(requestedAlgo) ? requestedAlgo : "SHA1"
    return Account(issuer: issuer, name: name, secret: secret,
                   digits: digits,
                   period: period,
                   algo: algo)
}

// MARK: - Keychain Persistence

struct KeychainManager {
    static let serviceName = "com.kapilthakare.totpbar"

    static func save(key: String, uri: String) {
        let data = uri.data(using: .utf8)!
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: key,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        ]
        SecItemDelete(query as CFDictionary)
        SecItemAdd(query as CFDictionary, nil)
    }

    static func loadAll() -> [Account] {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecReturnAttributes as String: true,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let items = item as? [[String: Any]] else {
            return []
        }
        var accounts: [Account] = []
        for dict in items {
            if let data = dict[kSecValueData as String] as? Data,
               let uriString = String(data: data, encoding: .utf8),
               let account = parse(uriString) {
                accounts.append(account)
            }
        }
        return accounts
    }

    static func delete(key: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: key
        ]
        SecItemDelete(query as CFDictionary)
    }
}

// MARK: - QR Scanner Window Controller

final class QRScannerWindowController: NSWindowController, AVCaptureMetadataOutputObjectsDelegate, NSWindowDelegate {
    var captureSession: AVCaptureSession?
    var onScanned: ((String) -> Void)?

    convenience init(onScanned: @escaping (String) -> Void) {
        let rect = NSRect(x: 0, y: 0, width: 500, height: 400)
        let window = NSWindow(contentRect: rect, styleMask: [.titled, .closable], backing: .buffered, defer: false)
        window.title = "Scan QR Code for 2FA"
        window.center()
        self.init(window: window)
        window.delegate = self
        self.onScanned = onScanned
        setupCamera(in: window.contentView!)
    }

    func setupCamera(in view: NSView) {
        let session = AVCaptureSession()
        captureSession = session

        guard let device = AVCaptureDevice.default(for: .video),
              let input = try? AVCaptureDeviceInput(device: device),
              session.canAddInput(input) else {
            let label = NSTextField(labelWithString: "Camera unavailable or permission denied.")
            label.frame = view.bounds
            label.alignment = .center
            view.addSubview(label)
            return
        }

        session.addInput(input)

        let output = AVCaptureMetadataOutput()
        guard session.canAddOutput(output) else { return }
        session.addOutput(output)
        output.setMetadataObjectsDelegate(self, queue: DispatchQueue.main)
        output.metadataObjectTypes = [.qr]

        let previewLayer = AVCaptureVideoPreviewLayer(session: session)
        previewLayer.frame = view.bounds
        previewLayer.videoGravity = .resizeAspectFill
        view.wantsLayer = true
        view.layer?.addSublayer(previewLayer)

        DispatchQueue.global(qos: .userInitiated).async {
            session.startRunning()
        }
    }

    func metadataOutput(_ output: AVCaptureMetadataOutput, didOutput metadataObjects: [AVMetadataObject], from connection: AVCaptureConnection) {
        captureSession?.stopRunning()
        if let obj = metadataObjects.first as? AVMetadataMachineReadableCodeObject,
           let str = obj.stringValue,
           let onScanned = onScanned {
            onScanned(str)
            window?.close()
        }
    }

    @objc func windowWillClose(_ notification: Notification) {
        captureSession?.stopRunning()
    }
}

// MARK: - App

final class App: NSObject, NSApplicationDelegate, NSMenuDelegate {
    let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
    let menu = NSMenu()
    var accounts: [Account] = []
    var favs: [String] = []
    var live: [(NSMenuItem, Account)] = []
    var timer: Timer?

    let dir = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".config/totp")
    var accountsURL: URL { dir.appendingPathComponent("accounts.txt") }
    var favsURL: URL { dir.appendingPathComponent("favorites.txt") }
    var hasLaunchedBeforeKey = "HasLaunchedBefore"

    func applicationDidFinishLaunching(_ n: Notification) {
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        migrateIfNeeded()
        menu.delegate = self
        item.menu = menu
        if let b = item.button {
            b.image = NSImage(systemSymbolName: "lock.shield", accessibilityDescription: "2FA")
        }

        // Check first launch / onboarding
        let defaults = UserDefaults.standard
        if !defaults.bool(forKey: hasLaunchedBeforeKey) {
            defaults.set(true, forKey: hasLaunchedBeforeKey)
            showWelcomeOnboarding()
        }
    }

    func migrateIfNeeded() {
        let existing = KeychainManager.loadAll()
        if existing.isEmpty {
            let text = (try? String(contentsOf: accountsURL, encoding: .utf8)) ?? ""
            let lines = text.split(whereSeparator: \.isNewline)
                .map { $0.trimmingCharacters(in: .whitespaces) }
                .filter { $0.hasPrefix("otpauth://") }
            for line in lines {
                if let acc = parse(line) {
                    KeychainManager.save(key: acc.key, uri: line)
                }
            }
        }
        let f = (try? String(contentsOf: favsURL, encoding: .utf8)) ?? ""
        favs = f.split(whereSeparator: \.isNewline)
            .map { $0.trimmingCharacters(in: .whitespaces).lowercased() }
            .filter { !$0.isEmpty }
    }

    func showWelcomeOnboarding() {
        let alert = NSAlert()
        alert.messageText = "Welcome to TOTPBar 🛡️"
        alert.informativeText = "TOTPBar is your secure, privacy-focused Mac menu bar app for Two-Factor Authentication.\n\nYour secrets are safely encrypted in the macOS Keychain. You can add your first 2FA account via Manual Entry, QR Code scanning, or Clipboard paste."
        alert.addButton(withTitle: "Get Started")
        alert.runModal()
    }

    // Data

    func load() {
        accounts = KeychainManager.loadAll()
            .sorted { $0.title.localizedCaseInsensitiveCompare($1.title) == .orderedAscending }
        let f = (try? String(contentsOf: favsURL, encoding: .utf8)) ?? ""
        favs = f.split(whereSeparator: \.isNewline)
            .map { $0.trimmingCharacters(in: .whitespaces).lowercased() }
            .filter { !$0.isEmpty }
    }

    func saveFavs() {
        try? favs.joined(separator: "\n").write(to: favsURL, atomically: true, encoding: .utf8)
    }

    // Menu

    func render(_ a: Account) -> NSAttributedString {
        let now = Date()
        let left = a.period - Int(now.timeIntervalSince1970) % a.period
        var code = totp(a, at: now)
        if code.count > 3 { code.insert(" ", at: code.index(code.startIndex, offsetBy: 3)) }
        let s = NSMutableAttributedString(string: a.title + "    ",
                                          attributes: [.font: NSFont.menuFont(ofSize: 0)])
        s.append(NSAttributedString(string: code, attributes: [
            .font: NSFont.monospacedDigitSystemFont(ofSize: NSFont.systemFontSize, weight: .semibold)]))
        s.append(NSAttributedString(string: "  \(left)s", attributes: [
            .font: NSFont.monospacedDigitSystemFont(ofSize: NSFont.smallSystemFontSize, weight: .regular),
            .foregroundColor: left <= 5 ? NSColor.systemRed : NSColor.secondaryLabelColor]))
        return s
    }

    func makeItem(_ a: Account) -> NSMenuItem {
        let mi = NSMenuItem(title: a.title, action: #selector(pick(_:)), keyEquivalent: "")
        mi.target = self
        mi.representedObject = a.key
        mi.attributedTitle = render(a)
        live.append((mi, a))
        return mi
    }

    func rebuild() {
        menu.removeAllItems()
        live = []

        if accounts.isEmpty {
            let welcomeItem = NSMenuItem(title: "No 2FA accounts found", action: nil, keyEquivalent: "")
            welcomeItem.isEnabled = false
            menu.addItem(welcomeItem)
            
            let addFirst = NSMenuItem(title: "Add your first account...", action: #selector(addAccountPrompt), keyEquivalent: "")
            addFirst.target = self
            menu.addItem(addFirst)
            menu.addItem(.separator())
        }

        let pinned = favs.compactMap { k in accounts.first { $0.key == k } }
        let pinnedKeys = Set(pinned.map { $0.key })
        for a in pinned { menu.addItem(makeItem(a)) }
        if !pinned.isEmpty { menu.addItem(.separator()) }

        let rest = accounts.filter { !pinnedKeys.contains($0.key) }
        if !rest.isEmpty {
            let parent = NSMenuItem(title: "All accounts (\(rest.count))", action: nil, keyEquivalent: "")
            let sub = NSMenu()
            for a in rest { sub.addItem(makeItem(a)) }
            parent.submenu = sub
            menu.addItem(parent)
        }

        menu.addItem(.separator())

        let addMenu = NSMenuItem(title: "Add Account...", action: #selector(addAccountPrompt), keyEquivalent: "n")
        addMenu.target = self
        menu.addItem(addMenu)

        let scanMenu = NSMenuItem(title: "Scan QR Code...", action: #selector(scanQRCode), keyEquivalent: "")
        scanMenu.target = self
        menu.addItem(scanMenu)

        let pasteMenu = NSMenuItem(title: "Import from Clipboard (otpauth://)", action: #selector(importFromClipboard), keyEquivalent: "v")
        pasteMenu.target = self
        menu.addItem(pasteMenu)

        menu.addItem(.separator())
        let hint = NSMenuItem(title: "Click = copy  ·  ⌥-click = pin / unpin", action: nil, keyEquivalent: "")
        hint.isEnabled = false
        menu.addItem(hint)
        let open = NSMenuItem(title: "Open accounts file / Backup", action: #selector(openFile), keyEquivalent: "")
        open.target = self
        menu.addItem(open)
        menu.addItem(NSMenuItem(title: "Quit", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q"))
    }

    func menuWillOpen(_ menu: NSMenu) {
        guard menu === self.menu else { return }
        load()
        rebuild()
        timer?.invalidate()
        let t = Timer(timeInterval: 1, repeats: true) { [weak self] _ in
            guard let self = self else { return }
            for (mi, a) in self.live { mi.attributedTitle = self.render(a) }
        }
        RunLoop.main.add(t, forMode: .common)
        timer = t
    }

    func menuDidClose(_ menu: NSMenu) {
        guard menu === self.menu else { return }
        timer?.invalidate()
        timer = nil
    }

    // Actions

    @objc func pick(_ sender: NSMenuItem) {
        guard let key = sender.representedObject as? String,
              let a = accounts.first(where: { $0.key == key }) else { return }
        if NSEvent.modifierFlags.contains(.option) {
            if let i = favs.firstIndex(of: key) { favs.remove(at: i) } else { favs.append(key) }
            saveFavs()
            return
        }
        copyCode(for: a)
    }

    func copyCode(for a: Account) {
        let code = totp(a)
        let pb = NSPasteboard.general
        pb.clearContents()
        pb.setString(code, forType: .string)
        pb.setData(Data(), forType: NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType"))
        let count = pb.changeCount
        DispatchQueue.main.asyncAfter(deadline: .now() + 30) {
            if NSPasteboard.general.changeCount == count { NSPasteboard.general.clearContents() }
        }
        let title = a.title
        let codeCopy = code
        if #available(macOS 10.14, *) {
            let center = UNUserNotificationCenter.current()
            center.requestAuthorization(options: [.alert, .sound]) { _, _ in }
            let content = UNMutableNotificationContent()
            content.title = "Copied " + title
            content.body = codeCopy
            let req = UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil)
            center.add(req)
        }
    }

    @objc func addAccountPrompt() {
        let alert = NSAlert()
        alert.messageText = "Add 2FA Account"
        alert.informativeText = "Paste an otpauth:// URI or fill in details manually."

        let stack = NSStackView(frame: NSRect(x: 0, y: 0, width: 320, height: 160))
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 8

        let uriField = NSTextField(frame: NSRect(x: 0, y: 0, width: 320, height: 24))
        uriField.placeholderString = "otpauth://totp/..."

        let issuerField = NSTextField(frame: NSRect(x: 0, y: 0, width: 320, height: 24))
        issuerField.placeholderString = "Issuer (e.g. GitHub)"

        let nameField = NSTextField(frame: NSRect(x: 0, y: 0, width: 320, height: 24))
        nameField.placeholderString = "Account Name (e.g. user@gmail.com)"

        let secretField = NSTextField(frame: NSRect(x: 0, y: 0, width: 320, height: 24))
        secretField.placeholderString = "Secret (Base32)"

        stack.addArrangedSubview(NSTextField(labelWithString: "URI:"))
        stack.addArrangedSubview(uriField)
        stack.addArrangedSubview(NSTextField(labelWithString: "Or Manual:"))
        stack.addArrangedSubview(issuerField)
        stack.addArrangedSubview(nameField)
        stack.addArrangedSubview(secretField)

        alert.accessoryView = stack
        alert.addButton(withTitle: "Add")
        alert.addButton(withTitle: "Cancel")

        let response = alert.runModal()
        if response == .alertFirstButtonReturn {
            let uri = uriField.stringValue.trimmingCharacters(in: .whitespaces)
            if !uri.isEmpty {
                if let acc = parse(uri) {
                    KeychainManager.save(key: acc.key, uri: uri)
                    load()
                    rebuild()
                }
            } else {
                let issuer = issuerField.stringValue.trimmingCharacters(in: .whitespaces)
                let name = nameField.stringValue.trimmingCharacters(in: .whitespaces)
                let secret = secretField.stringValue.trimmingCharacters(in: .whitespaces)
                if !secret.isEmpty {
                    let constructed = "otpauth://totp/\(issuer):\(name)?secret=\(secret)&issuer=\(issuer)"
                    if let acc = parse(constructed) {
                        KeychainManager.save(key: acc.key, uri: constructed)
                        load()
                        rebuild()
                    }
                }
            }
        }
    }

    @objc func importFromClipboard() {
        let pb = NSPasteboard.general
        guard let str = pb.string(forType: .string)?.trimmingCharacters(in: .whitespacesAndNewlines),
              str.hasPrefix("otpauth://"),
              let acc = parse(str) else {
            let alert = NSAlert()
            alert.messageText = "Import Failed"
            alert.informativeText = "No valid otpauth:// URI found in clipboard."
            alert.runModal()
            return
        }
        KeychainManager.save(key: acc.key, uri: str)
        load()
        rebuild()
        let alert = NSAlert()
        alert.messageText = "Account Added"
        alert.informativeText = "Successfully imported \(acc.title)."
        alert.runModal()
    }

    var scannerController: QRScannerWindowController?

    @objc func scanQRCode() {
        scannerController = QRScannerWindowController { [weak self] uri in
            if let acc = parse(uri) {
                KeychainManager.save(key: acc.key, uri: uri)
                self?.load()
                self?.rebuild()
            }
        }
        scannerController?.showWindow(nil)
        scannerController?.window?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    @objc func openFile() {
        if !FileManager.default.fileExists(atPath: accountsURL.path) {
            let initial = accounts.map { $0.uriString }.joined(separator: "\n")
            try? initial.write(to: accountsURL, atomically: true, encoding: .utf8)
        }
        NSWorkspace.shared.open(accountsURL)
    }
}

// MARK: - Entry

let app = NSApplication.shared
let delegate = App()
app.delegate = delegate
app.setActivationPolicy(.accessory)
app.run()
