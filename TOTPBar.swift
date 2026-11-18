import Cocoa
import CryptoKit
import AVFoundation
import UserNotifications
import Security

// MARK: - Model

struct Account {
    let issuer: String
    let name: String
    let secret: Data
    let digits: Int
    let period: Int
    let algo: String

    init(issuer: String, name: String, secret: Data, digits: Int = 6, period: Int = 30, algo: String = "SHA1") {
        self.issuer = issuer
        self.name = name
        self.secret = secret
        self.digits = digits
        self.period = period
        self.algo = algo
    }

    var title: String {
        if issuer.isEmpty { return name }
        if name.isEmpty { return issuer }
        return "\(issuer) (\(name))"
    }
    var key: String { "\(issuer):\(name)".lowercased() }
}

// MARK: - Base32 / TOTP

func base32Decode(_ s: String) -> Data? {
    let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
    var bits = 0
    var value = 0
    var out = [UInt8]()
    for c in s.uppercased() where c != "=" && c != " " && c != "-" {
        guard let idx = alphabet.firstIndex(of: c) else { return nil }
        value = (value << 5) | Int(idx)
        bits += 5
        if bits >= 8 {
            out.append(UInt8((value >> (bits - 8)) & 0xFF))
            bits -= 8
            value &= (1 << bits) - 1
        }
    }
    return Data(out)
}

func base32Encode(_ data: Data) -> String {
    let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
    var bits = UInt64(0)
    var bitCount = Int(0)
    var out = ""
    for byte in [UInt8](data) {
        bits = (bits << 8) | UInt64(byte)
        bitCount += 8
        while bitCount >= 5 {
            bitCount -= 5
            out.append(String(alphabet[Int((bits >> UInt(bitCount)) & 31)]))
        }
        bits = bitCount > 0 ? (bits & ((UInt64(1) << UInt(bitCount)) - 1)) : 0
    }
    let padding = (8 - (out.count % 8)) % 8
    return out + String(repeating: "=", count: padding)
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

enum TOTPKeychain {
    static let service = "com.kapilthakare.totpbar"
    static let accountsItem = "totpbar.accounts"

    static func save(accounts: [Account]) {
        var objects: [[String: Any]] = []
        for a in accounts {
            objects.append([
                "issuer": a.issuer,
                "name": a.name,
                "secret": base32Encode(a.secret),
                "digits": a.digits,
                "period": a.period,
                "algo": a.algo,
            ])
        }
        let data = (try? JSONSerialization.data(withJSONObject: objects, options: [])) ?? Data()
        let query = [kSecClass: kSecClassGenericPassword, kSecAttrService: service, kSecAttrAccount: accountsItem] as CFDictionary
        var value: AnyObject? = nil
        value = NSData(data: data)
        let status = SecItemAdd(query, &value)
        if status == errSecDuplicateItem {
            // Item already exists — delete and re-add with the fresh value.
            SecItemDelete(query)
            SecItemAdd(query, &value)
        }
    }

    static func load() -> [Account] {
        let query = [kSecClass: kSecClassGenericPassword, kSecAttrService: service, kSecAttrAccount: accountsItem] as CFDictionary
        var result: AnyObject? = nil
        let status = SecItemCopyMatching(query, &result)
        guard status == errSecSuccess, let data = result as? Data else { return [] }
        guard let json = try? JSONSerialization.jsonObject(with: data, options: []) as? [[String: Any]] else { return [] }
        return json.compactMap { dict -> Account? in
            guard let secretB32 = dict["secret"] as? String else { return nil }
            guard let secret = base32Decode(secretB32) else { return nil }
            return Account(
                issuer: dict["issuer"] as? String ?? "",
                name: dict["name"] as? String ?? "",
                secret: secret,
                digits: dict["digits"] as? Int ?? 6,
                period: dict["period"] as? Int ?? 30,
                algo: dict["algo"] as? String ?? "SHA1",
            )
        }
    }
}

// MARK: - App

final class App: NSObject, NSApplicationDelegate, NSMenuDelegate, AVCaptureMetadataOutputObjectsDelegate, NSWindowDelegate {
    let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
    let menu = NSMenu()
    var accounts: [Account] = []
    var favs: [String] = []
    var live: [(NSMenuItem, Account)] = []
    var timer: Timer?
    var scannerWindow: NSWindow?

    let session = AVCaptureSession()
    let output = AVCaptureMetadataOutput()

    let quickCodes: [(String, String)] = [
        ("Magento Admin", "primesandzooms.com:kapil.thakare@primesandzooms.com"),
        ("SureMDM Console", "suremdm:42gears"),
    ]

    override init() {
        super.init()
        menu.delegate = self
        item.menu = menu
        NSApplication.shared.delegate = self
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApplication.shared.setActivationPolicy(.accessory)
        if let b = item.button {
            b.image = NSImage(systemSymbolName: "lock.shield", accessibilityDescription: "2FA")
        }
        migrateFromLegacyFile()
        load()
        rebuild()
        DispatchQueue.main.async { self.showWelcomeIfNeeded() }
    }

    // MARK: - Persistence (Keychain)

    func migrateFromLegacyFile() {
        let dir = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".config/totp")
        let accountsURL = dir.appendingPathComponent("accounts.txt")
        let favsURL = dir.appendingPathComponent("favorites.txt")

        if FileManager.default.fileExists(atPath: accountsURL.path) {
            if let text = try? String(contentsOf: accountsURL, encoding: .utf8) {
                var parsed: [Account] = []
                for line in text.split(separator: "\n") {
                    let l = line.trimmingCharacters(in: .whitespaces)
                    if l.hasPrefix("otpauth://"), let a = parse(String(l)) {
                        parsed.append(a)
                    }
                }
                if !parsed.isEmpty { TOTPKeychain.save(accounts: parsed) }
            }
            try? FileManager.default.removeItem(at: accountsURL)
        }
        if FileManager.default.fileExists(atPath: favsURL.path) {
            if let f = try? String(contentsOf: favsURL, encoding: .utf8) {
                favs = f.split(separator: "\n")
                    .map { $0.trimmingCharacters(in: .whitespaces).lowercased() }
                    .filter { !$0.isEmpty }
            }
            UserDefaults.standard.set(favs, forKey: "favKeys")
            try? FileManager.default.removeItem(at: favsURL)
        }
        UserDefaults.standard.set(favs, forKey: "favKeys")
    }

    func load() {
        accounts = TOTPKeychain.load()
        accounts = accounts.sorted { $0.title.localizedCaseInsensitiveCompare($1.title) == .orderedAscending }
        favs = UserDefaults.standard.array(forKey: "favKeys") as? [String] ?? []
        favs = favs.map { $0.lowercased() }.filter { !$0.isEmpty }
    }

    func saveFavs() { UserDefaults.standard.set(favs, forKey: "favKeys") }

    // MARK: - Onboarding / Welcome

    func showWelcomeIfNeeded() {
        let defaults = UserDefaults.standard
        if defaults.bool(forKey: "TOTPBar.hasSeenWelcome") { return }
        defaults.set(true, forKey: "TOTPBar.hasSeenWelcome")
        showWelcome()
    }

    func showWelcome() {
        let alert = NSAlert()
        alert.messageText = "Welcome to TOTPBar"
        alert.informativeText = "TOTPBar generates time-based one-time passwords (2FA codes) from your saved accounts and shows them in the menu bar.\n\n" +
            "• Secrets are stored in your Keychain — never in plaintext on disk.\n" +
            "• Add your first token via “Scan QR Code…”, “Paste from Clipboard”, or manual entry.\n" +
            "• QR scanning will ask for Camera access the first time you use it.\n" +
            "• Click a token to copy its code to the clipboard (auto-clears after 30s, concealed from clipboard managers)."
        alert.addButton(withTitle: "Add Your First Token")
        alert.addButton(withTitle: "Not Now")
        let resp = alert.runModal()
        if resp == NSApplication.ModalResponse.alertFirstButtonReturn {
            presentAddManual()
        }
    }

    // MARK: - Add Account (manual + otpauth URI)

    func presentAddManual() {
        let alert = NSAlert()
        alert.messageText = "Add TOTP Account"
        alert.informativeText = "Paste a full otpauth://totp URI into the Secret field, or type the Base32 secret plus its details manually. Secrets are stored in your Keychain."
        let container = NSView(frame: NSRect(x: 0, y: 0, width: 380, height: 252))
        let secretField = NSTextField(frame: NSRect(x: 10, y: 196, width: 360, height: 24))
        let issuerField = NSTextField(frame: NSRect(x: 10, y: 156, width: 360, height: 24))
        let labelField = NSTextField(frame: NSRect(x: 10, y: 116, width: 360, height: 24))
        let algoField = NSTextField(frame: NSRect(x: 10, y: 76, width: 360, height: 24))
        let digitsField = NSTextField(frame: NSRect(x: 10, y: 36, width: 360, height: 24))
        let periodField = NSTextField(frame: NSRect(x: 10, y: 4, width: 360, height: 24))
        alert.accessoryView = container

        alert.addButton(withTitle: "Add")
        alert.addButton(withTitle: "Cancel")
        let resp = alert.runModal()
        guard resp == NSApplication.ModalResponse.alertFirstButtonReturn else { return }

        let str = { (f: NSTextField) -> String in
            f.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        }
        let secretRaw = str(secretField)
        let issuer = str(issuerField)
        let label = str(labelField)
        let algo = str(algoField).uppercased()
        let digits = Int(str(digitsField)) ?? 6
        let period = Int(str(periodField)) ?? 30

        if secretRaw.lowercased().hasPrefix("otpauth://"), let a = parse(secretRaw) {
            insertAccount(a)
            return
        }
        guard let secretData = base32Decode(secretRaw) else {
            presentAlert("Invalid Secret", message: "Could not decode the Base32 secret. Please check the secret and try again.")
            return
        }
        let finalAlgo = ["SHA1", "SHA256", "SHA512"].contains(algo) ? algo : "SHA1"
        let account = Account(issuer: issuer, name: label, secret: secretData,
                              digits: min(max(digits, 6), 8), period: max(1, period), algo: finalAlgo)
        insertAccount(account)
    }

    // MARK: - QR scanning

    @objc func scanQR(_ sender: NSMenuItem) {
        AVCaptureDevice.requestAccess(for: .video) { [weak self] granted in
            DispatchQueue.main.async {
                if granted {
                    self?.presentScanner()
                } else {
                    self?.presentAlert("Camera Access Required", message: "TOTPBar needs camera access to scan QR codes that contain your two-factor authentication secrets.")
                }
            }
        }
    }

    func presentScanner() {
        guard scannerWindow == nil else { return }
        let window = NSWindow()
        window.title = "Scan QR Code"
        window.styleMask = [.titled, .closable]
        window.isMovableByWindowBackground = true
        window.delegate = self
        let view = NSView(frame: NSRect(x: 0, y: 0, width: 400, height: 480))
        view.autoresizingMask = [.width, .height]
        let preview = AVCaptureVideoPreviewLayer()
        preview.session = session
        preview.videoGravity = .resizeAspectFill
        preview.frame = view.bounds
        view.layer?.addSublayer(preview)
        window.contentView = view
        window.makeKeyAndOrderFront(nil)
        scannerWindow = window
        session.startRunning()
    }

    func stopScanner() {
        session.stopRunning()
    }

    @objc func cancelScan(_ sender: NSButton) {
        stopScanner()
        scannerWindow = nil
    }

    func windowShouldClose(_ window: NSWindow) -> Bool {
        stopScanner()
        scannerWindow = nil
        return true
    }

    // MARK: - AVCaptureMetadataOutputObjectsDelegate

    func captureOutput(_ output: AVCaptureMetadataOutput, didOutput metadataObjects: [AVMetadataObject], from connection: AVCaptureConnection) {
        for o in metadataObjects {
            if let machine = o as? AVMetadataMachineReadableCodeObject, let value = machine.stringValue, !value.isEmpty {
                stopScanner()
                scannerWindow = nil
                handleDetectedURI(value)
                return
            }
        }
    }

    func handleDetectedURI(_ uriString: String) {
        guard let a = parse(uriString) else {
            presentAlert("Invalid QR Code", message: "Could not read a valid otpauth://totp URI from the QR code. Try again with a standard 2FA QR code.")
            return
        }
        insertAccount(a)
    }

    // MARK: - Clipboard import

    @objc func importClipboard(_ sender: NSMenuItem) {
        let text = NSPasteboard.general.string(forType: .string) ?? ""
        let uris = text.split(separator: "\n").map { $0.trimmingCharacters(in: .whitespaces) }.filter { $0.hasPrefix("otpauth://") }
        guard !uris.isEmpty else {
            presentAlert("Clipboard Empty", message: "No otpauth:// URI was found on the clipboard. Paste a TOTP URI (otpauth://totp/...) and try again.")
            return
        }
        for u in uris {
            guard let a = parse(String(u)) else { continue }
            insertAccount(a)
        }
    }

    // MARK: - Present alert

    func presentAlert(_ title: String, message: String) {
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = message
        alert.addButton(withTitle: "OK")
        _ = alert.runModal()
    }

    // MARK: - Account management

    func insertAccount(_ a: Account) {
        if accounts.contains(where: { $0.key == a.key }) { return }
        accounts.append(a)
        accounts = accounts.sorted { $0.title.localizedCaseInsensitiveCompare($1.title) == .orderedAscending }
        TOTPKeychain.save(accounts: accounts)
        rebuild()
    }

    func addAccount(_ a: Account) {
        insertAccount(a)
        presentAlert("Account Added", message: "\(a.title) was saved to your Keychain.")
    }

    // MARK: - Menu

    func render(_ a: Account) -> NSAttributedString {
        let now = Date()
        let left = a.period - Int(now.timeIntervalSince1970) % a.period
        var code = totp(a, at: now)
        if code.count > 3 { code.insert(" ", at: code.index(code.startIndex, offsetBy: 3)) }
        let s = NSMutableAttributedString(string: a.title + "    ",
                                          attributes: [.font: NSFont.menuFont(ofSize: NSFont.systemFontSize)])
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

        if !accounts.isEmpty {
            for (label, key) in quickCodes {
                let mi = NSMenuItem(title: label, action: #selector(copyQuickCode(_:)), keyEquivalent: "")
                mi.target = self
                mi.representedObject = key
                mi.image = NSImage(systemSymbolName: "doc.on.doc", accessibilityDescription: label)
                menu.addItem(mi)
            }
            menu.addItem(.separator())
        }

        if accounts.isEmpty {
            let add = NSMenuItem(title: "Add Your First Token…", action: #selector(addAccountFromPrompt(_:)), keyEquivalent: "")
            add.target = self
            menu.addItem(add)
            let scan = NSMenuItem(title: "Scan QR Code…", action: #selector(scanQR(_:)), keyEquivalent: "")
            scan.target = self
            menu.addItem(scan)
            let paste = NSMenuItem(title: "Paste from Clipboard", action: #selector(importClipboard(_:)), keyEquivalent: "")
            paste.target = self
            menu.addItem(paste)
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
        let hint = NSMenuItem(title: "Click = copy  ·  ⌥-click = pin / unpin", action: nil, keyEquivalent: "")
        hint.isEnabled = false
        menu.addItem(hint)
        let addAll = NSMenuItem(title: "Add Account…", action: #selector(addAccountFromPrompt(_:)), keyEquivalent: "")
        addAll.target = self
        menu.addItem(addAll)
        let scanAll = NSMenuItem(title: "Scan QR Code…", action: #selector(scanQR(_:)), keyEquivalent: "")
        scanAll.target = self
        menu.addItem(scanAll)
        let pasteAll = NSMenuItem(title: "Import from Clipboard", action: #selector(importClipboard(_:)), keyEquivalent: "")
        pasteAll.target = self
        menu.addItem(pasteAll)
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

    // MARK: - Actions

    @objc func copyQuickCode(_ sender: NSMenuItem) {
        guard let key = sender.representedObject as? String,
              let a = accounts.first(where: { $0.key == key }) else { return }
        copyCode(for: a)
    }

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
        pb.setData(Data(code.utf8), forType: NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType"))
        let count = pb.changeCount
        DispatchQueue.main.asyncAfter(deadline: .now() + 30) {
            if NSPasteboard.general.changeCount == count { NSPasteboard.general.clearContents() }
        }
        let center = UNUserNotificationCenter.current()
        center.requestAuthorization(options: [.alert, .sound]) { _, _ in }
        let content = UNMutableNotificationContent()
        content.title = "Copied " + a.title
        content.body = code
        let req = UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil)
        center.add(req)
    }

    @objc func addAccountFromPrompt(_ sender: NSMenuItem) {
        presentAddManual()
    }
}

// MARK: - Entry

let app = NSApplication.shared
let delegate = App()
app.delegate = delegate
app.setActivationPolicy(.accessory)
app.run()
