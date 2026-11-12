import Foundation
import EphedrineCore

/// Fetches Claude plan usage with Claude Code's own sign-in.
///
/// Claude Code keeps its OAuth tokens in the login keychain (item
/// "Claude Code-credentials") or in `~/.claude/.credentials.json`. The access
/// token only lasts a few hours and Claude Code renews it only while it runs,
/// so a meter that just reads it goes blank a few hours after Claude Code was
/// last used. When it has expired, this renews it the way Claude Code does
/// (the refresh token at the token endpoint) and writes the result back in
/// place, keeping every other field, so Claude Code picks up the same tokens.
///
/// All work happens on one serial queue; the completion runs on main.
final class ClaudeUsageClient {
    enum Source: Equatable, CustomStringConvertible {
        case keychain(account: String?)
        case file(String)
        var description: String {
            switch self {
            case .keychain: return "keychain"
            case .file(let p): return (p as NSString).abbreviatingWithTildeInPath
            }
        }
    }

    private struct Loaded {
        let source: Source
        let raw: String
        let oauth: ClaudeOAuth
    }

    private enum LoadFailure: Error { case missing, noClaudeLogin, denied }

    private let queue = DispatchQueue(label: "ephedrine.usage", qos: .utility)
    private let userAgent: String
    /// A renewed sign-in that couldn't be written back: used until it expires,
    /// so the old (now spent) refresh token isn't tried again.
    private var unsaved: Loaded?

    init(appVersion: String) { userAgent = "Ephedrine/\(appVersion) (macOS)" }

    func fetch(consecutiveFailures: Int, completion: @escaping (Result<[UsageLimit], UsageProblem>) -> Void) {
        queue.async { [self] in
            let r = run(consecutiveFailures: consecutiveFailures)
            DispatchQueue.main.async { completion(r) }
        }
    }

    // MARK: the fetch

    private func run(consecutiveFailures: Int) -> Result<[UsageLimit], UsageProblem> {
        var loaded: Loaded
        switch load() {
        case .success(let l): loaded = l
        case .failure(let p): return .failure(p)
        }
        guard loaded.oauth.canReadUsage else { return .failure(.missingScope) }

        var renewed = false
        if loaded.oauth.isExpired(now: Date()) {
            switch renew(loaded, consecutiveFailures: consecutiveFailures) {
            case .success(let l): loaded = l; renewed = true
            case .failure(let p): return .failure(p)
            }
        }

        var r = requestUsage(loaded.oauth.accessToken, consecutiveFailures: consecutiveFailures)
        if case .failure(.signInExpired) = r {
            // Claude Code may have renewed it a moment ago: read it again first.
            if case .success(let again) = load(), again.oauth.accessToken != loaded.oauth.accessToken {
                loaded = again
                r = requestUsage(loaded.oauth.accessToken, consecutiveFailures: consecutiveFailures)
            } else if !renewed {
                switch renew(loaded, consecutiveFailures: consecutiveFailures) {
                case .success(let l): r = requestUsage(l.oauth.accessToken, consecutiveFailures: consecutiveFailures)
                case .failure(let p): return .failure(p)
                }
            }
        }
        return r
    }

    private func requestUsage(_ token: String, consecutiveFailures: Int) -> Result<[UsageLimit], UsageProblem> {
        guard let url = URL(string: claudeUsageURL) else { return .failure(.unexpectedResponse) }
        var req = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 20)
        req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        req.setValue("oauth-2025-04-20", forHTTPHeaderField: "anthropic-beta")
        req.setValue("application/json", forHTTPHeaderField: "Accept")
        req.setValue(userAgent, forHTTPHeaderField: "User-Agent")
        let resp = send(req)
        guard let status = resp.status else { return .failure(.offline) }
        guard (200..<300).contains(status) else {
            return .failure(usageProblem(status: status, body: resp.data, retryAfter: resp.retryAfter,
                                         consecutiveFailures: consecutiveFailures, now: Date()))
        }
        guard let d = resp.data, let j = (try? JSONSerialization.jsonObject(with: d)) as? [String: Any] else {
            return .failure(.unexpectedResponse)
        }
        let limits = parseUsageLimits(j)
        return limits.isEmpty ? .failure(.unexpectedResponse) : .success(limits)
    }

    // MARK: renewing

    private func renew(_ l: Loaded, consecutiveFailures: Int) -> Result<Loaded, UsageProblem> {
        guard let refresh = l.oauth.refreshToken else { return .failure(.signInExpired) }
        let body: [String: Any] = ["grant_type": "refresh_token", "refresh_token": refresh,
                                   "client_id": claudeCodeOAuthClientID]
        guard let bodyData = try? JSONSerialization.data(withJSONObject: body) else { return .failure(.unexpectedResponse) }

        var lastProblem: UsageProblem = .offline
        for endpoint in claudeOAuthTokenURLs {
            guard let url = URL(string: endpoint) else { continue }
            var req = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 20)
            req.httpMethod = "POST"
            req.httpBody = bodyData
            req.setValue("application/json", forHTTPHeaderField: "Content-Type")
            req.setValue("application/json", forHTTPHeaderField: "Accept")
            req.setValue(userAgent, forHTTPHeaderField: "User-Agent")
            let resp = send(req)
            guard let status = resp.status else { lastProblem = .offline; continue }
            if (200..<300).contains(status) {
                guard let d = resp.data,
                      let j = (try? JSONSerialization.jsonObject(with: d)) as? [String: Any],
                      let grant = parseTokenGrant(j, now: Date()) else { return .failure(.unexpectedResponse) }
                return .success(store(grant, over: l))
            }
            if status == 400 || status == 401 {
                // invalid_grant: the refresh token was spent or revoked. Signing in again is the only fix.
                logLine("usage: renewing Claude Code's sign-in failed (\(status)), a new /login is needed")
                return .failure(.signInExpired)
            }
            if status == 429 {
                return .failure(usageProblem(status: 429, body: resp.data, retryAfter: resp.retryAfter,
                                             consecutiveFailures: consecutiveFailures, now: Date()))
            }
            lastProblem = .server(status)   // a 404 or 5xx here: try the other host
        }
        return .failure(lastProblem)
    }

    /// Writes the renewed tokens back where they came from, and checks they stuck.
    private func store(_ grant: TokenGrant, over l: Loaded) -> Loaded {
        let oauth = ClaudeOAuth(accessToken: grant.accessToken,
                                refreshToken: grant.refreshToken ?? l.oauth.refreshToken,
                                expiresAt: grant.expiresAt, scopes: grant.scopes ?? l.oauth.scopes,
                                subscriptionType: l.oauth.subscriptionType)
        guard let merged = mergeTokenGrant(into: l.raw, grant) else {
            logLine("usage: renewed Claude Code's sign-in but couldn't merge it into \(l.source)")
            let kept = Loaded(source: l.source, raw: l.raw, oauth: oauth)
            unsaved = kept
            return kept
        }
        let saved: Bool
        switch l.source {
        case .keychain(let account): saved = writeKeychain(merged, account: account)
        case .file(let path):        saved = writeFile(merged, path: path)
        }
        let result = Loaded(source: l.source, raw: merged, oauth: oauth)
        if saved {
            unsaved = nil
            logLine("usage: renewed Claude Code's sign-in (\(l.source))")
        } else {
            unsaved = result
            logLine("usage: renewed Claude Code's sign-in but couldn't save it to \(l.source); Claude Code may ask you to /login again")
        }
        return result
    }

    // MARK: reading the sign-in

    private var credentialsFiles: [String] {
        var dirs: [String] = []
        if let d = ProcessInfo.processInfo.environment["CLAUDE_CONFIG_DIR"], !d.isEmpty { dirs.append(d) }
        dirs.append("\(NSHomeDirectory())/.claude")
        return dirs.map { ($0 as NSString).appendingPathComponent(".credentials.json") }
    }

    /// The best sign-in on this Mac: a fresh one first, then one that can be renewed.
    private func load() -> Result<Loaded, UsageProblem> {
        if let u = unsaved, !u.oauth.isExpired(now: Date()) { return .success(u) }

        var found: [Loaded] = []
        var failures: [LoadFailure] = []
        switch readKeychain() {
        case .success(let l): found.append(l)
        case .failure(let f): failures.append(f)
        }
        for path in credentialsFiles {
            guard let text = try? String(contentsOfFile: path, encoding: .utf8) else { continue }
            switch parseClaudeCredentials(text) {
            case .found(let o): found.append(Loaded(source: .file(path), raw: text, oauth: o))
            case .noClaudeLogin: failures.append(.noClaudeLogin)
            case .malformed: break
            }
        }
        let now = Date()
        if let fresh = found.filter({ !$0.oauth.isExpired(now: now) })
            .max(by: { ($0.oauth.expiresAt ?? .distantPast) < ($1.oauth.expiresAt ?? .distantPast) }) {
            return .success(fresh)
        }
        if let renewable = found.first(where: { $0.oauth.refreshToken != nil }) { return .success(renewable) }
        if let any = found.first { return .success(any) }
        if failures.contains(.denied) { return .failure(.keychainDenied) }
        return .failure(claudeCLIInstalled ? .notSignedIn : .cliNotInstalled)
    }

    private var claudeCLIInstalled: Bool {
        claudeCLICandidates(home: NSHomeDirectory()).contains { FileManager.default.isExecutableFile(atPath: $0) }
    }

    private func readKeychain() -> Result<Loaded, LoadFailure> {
        // `security` created Claude Code's item, so it's on the item's access
        // list: no prompt for it, and none again after one Always Allow.
        let r = runProcess("/usr/bin/security", ["find-generic-password", "-s", claudeKeychainService, "-w"], timeout: 90)
        switch r.status {
        case 0: break
        case 44: return .failure(.missing)                       // errSecItemNotFound
        default:
            logLine("usage: keychain read failed (security exit \(r.status)\(r.timedOut ? ", timed out" : ""))")
            return .failure(.denied)
        }
        switch parseClaudeCredentials(r.out) {
        case .found(let o):
            return .success(Loaded(source: .keychain(account: keychainAccount()), raw: r.out.trimmingCharacters(in: .newlines), oauth: o))
        case .noClaudeLogin: return .failure(.noClaudeLogin)
        case .malformed: return .failure(.missing)
        }
    }

    /// The item's account name, needed to update it in place. Reading the
    /// attributes (no `-w`) never asks for permission.
    private func keychainAccount() -> String? {
        let r = runProcess("/usr/bin/security", ["find-generic-password", "-s", claudeKeychainService], timeout: 15)
        return parseKeychainAccount(r.out + "\n" + r.err)
    }

    // MARK: writing it back

    /// Same command Claude Code uses: `security -i` reads it from stdin and
    /// `-X` takes hex, so the tokens never appear in a process listing.
    private func writeKeychain(_ json: String, account: String?) -> Bool {
        let acct = account ?? NSUserName()
        let quoted = { (s: String) in "\"" + s.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"") + "\"" }
        let cmd = "add-generic-password -U -a \(quoted(acct)) -s \(quoted(claudeKeychainService)) -X \(hexEncoded(json))\n"
        guard runWithInput("/usr/bin/security", ["-i"], input: cmd, timeout: 60) == 0 else { return false }
        // Confirm it reads back as written before relying on it.
        let check = runProcess("/usr/bin/security", ["find-generic-password", "-s", claudeKeychainService, "-w"], timeout: 60)
        guard check.status == 0, case .found(let o) = parseClaudeCredentials(check.out),
              case .found(let want) = parseClaudeCredentials(json) else { return false }
        return o.accessToken == want.accessToken
    }

    private func writeFile(_ json: String, path: String) -> Bool {
        let url = URL(fileURLWithPath: path)
        let tmp = url.deletingLastPathComponent().appendingPathComponent(".credentials.json.ephedrine-\(getpid())")
        do {
            try Data(json.utf8).write(to: tmp, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: tmp.path)
            _ = try FileManager.default.replaceItemAt(url, withItemAt: tmp)
            return true
        } catch {
            try? FileManager.default.removeItem(at: tmp)
            return false
        }
    }

    // MARK: plumbing

    private struct HTTPResult { let status: Int?; let data: Data?; let retryAfter: String? }

    /// A blocking request; only ever called on `queue`.
    private func send(_ req: URLRequest) -> HTTPResult {
        let done = DispatchSemaphore(value: 0)
        var result = HTTPResult(status: nil, data: nil, retryAfter: nil)
        URLSession.shared.dataTask(with: req) { d, resp, _ in
            let http = resp as? HTTPURLResponse
            result = HTTPResult(status: http?.statusCode, data: d, retryAfter: http?.value(forHTTPHeaderField: "Retry-After"))
            done.signal()
        }.resume()
        if done.wait(timeout: .now() + req.timeoutInterval + 5) == .timedOut { return HTTPResult(status: nil, data: nil, retryAfter: nil) }
        return result
    }

    private func runWithInput(_ path: String, _ args: [String], input: String, timeout: TimeInterval) -> Int32 {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: path)
        p.arguments = args
        let inPipe = Pipe()
        p.standardInput = inPipe
        p.standardOutput = FileHandle.nullDevice
        p.standardError = FileHandle.nullDevice
        let exited = DispatchSemaphore(value: 0)
        p.terminationHandler = { _ in exited.signal() }
        do { try p.run() } catch { return -1 }
        inPipe.fileHandleForWriting.write(Data(input.utf8))
        try? inPipe.fileHandleForWriting.close()
        if exited.wait(timeout: .now() + timeout) == .timedOut { p.terminate(); return -2 }
        return p.terminationStatus
    }
}
