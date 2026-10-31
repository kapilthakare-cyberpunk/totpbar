import Cocoa
import CryptoKit

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
}

// MARK: - Base32 / TOTP

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

    func applicationDidFinishLaunching(_ n: Notification) {
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        menu.delegate = self
        item.menu = menu
        if let b = item.button {
            b.image = NSImage(systemSymbolName: "lock.shield", accessibilityDescription: "2FA")
        }
    }

    // Data

    func load() {
        let text = (try? String(contentsOf: accountsURL, encoding: .utf8)) ?? ""
        accounts = text.split(whereSeparator: \.isNewline)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { $0.hasPrefix("otpauth://") }
            .compactMap(parse)
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
            let mi = NSMenuItem(title: "No accounts found in ~/.config/totp/accounts.txt",
                                action: nil, keyEquivalent: "")
            mi.isEnabled = false
            menu.addItem(mi)
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
        let fetch = NSMenuItem(title: "Fetch admin codes", action: #selector(fetchAndCopyAdmin), keyEquivalent: "")
        fetch.target = self
        menu.addItem(fetch)
        let hint = NSMenuItem(title: "Click = copy  ·  ⌥-click = pin / unpin", action: nil, keyEquivalent: "")
        hint.isEnabled = false
        menu.addItem(hint)
        let open = NSMenuItem(title: "Open accounts file", action: #selector(openFile), keyEquivalent: "")
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
        let code = totp(a)
        let pb = NSPasteboard.general
        pb.clearContents()
        pb.setString(code, forType: .string)
        pb.setData(Data(), forType: NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType"))
        let count = pb.changeCount
        DispatchQueue.main.asyncAfter(deadline: .now() + 30) {
            if NSPasteboard.general.changeCount == count { NSPasteboard.general.clearContents() }
        }
    }

    @objc func openFile() {
        if !FileManager.default.fileExists(atPath: accountsURL.path) {
            FileManager.default.createFile(atPath: accountsURL.path, contents: Data(),
                                           attributes: [.posixPermissions: 0o600])
        }
        NSWorkspace.shared.open(accountsURL)
    }

    // MARK: - Website code fetching / clipboard

    func fetchSite(_ urlString: String, completion: @escaping (String?) -> Void) {
        guard let url = URL(string: urlString) else { completion(nil); return }
        URLSession.shared.dataTask(with: url) { data, _, _ in
            if let data = data {
                completion(String(data: data, encoding: .utf8) ?? String(data: data, encoding: .isoLatin1))
            } else {
                completion(nil)
            }
        }.resume()
    }

    func tokenPairs(from html: String) -> [String: String] {
        var pairs: [String: String] = [:]
        guard let regex = try? NSRegularExpression(pattern: "<input[^>]*>", options: [.caseInsensitive]),
              let nameRe = try? NSRegularExpression(pattern: "name\\s*=\\s*\"([^\"]*)\""),
              let valueRe = try? NSRegularExpression(pattern: "value\\s*=\\s*\"([^\"]*)\"") else { return pairs }
        let matches = regex.matches(in: html, range: NSRange(location: 0, length: Int(html.utf16.count)))
        for m in matches {
            let tag = (html as NSString).substring(with: m.range)
            let nRange = NSRange(location: 0, length: Int((tag as NSString).length))
            if let nm = nameRe.firstMatch(in: tag, range: nRange), nm.range(at: 1).location != NSNotFound {
                let name = (tag as NSString).substring(with: nm.range(at: 1))
                var value = ""
                if let vm = valueRe.firstMatch(in: tag, range: nRange), vm.range(at: 1).location != NSNotFound {
                    value = (tag as NSString).substring(with: vm.range(at: 1))
                }
                pairs[name] = value
            }
        }
        return pairs
    }

    @objc func fetchAndCopyAdmin() {
        let urls = [
            "https://primesandzooms.com/",
            "https://primesandzooms.in.suremdm.io/console/v3/"
        ]
        var results: [String] = []
        var remaining = urls.count
        for u in urls {
            fetchSite(u) { html in
                if let html = html, !html.isEmpty {
                    results.append("URL: \(u)\n\(self.tokenPairs(from: html))")
                }
                remaining -= 1
                if remaining <= 0 {
                    let text = results.joined(separator: "\n\n")
                    let pb = NSPasteboard.general
                    pb.clearContents()
                    pb.setString(text, forType: .string)
                }
            }
        }
    }
}

// MARK: - Entry

let app = NSApplication.shared
let delegate = App()
app.delegate = delegate
app.setActivationPolicy(.accessory)
app.run()
