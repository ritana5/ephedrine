import Foundation

// Claude Code's sign-in, as the usage meter needs it: parsing the stored
// credentials, renewing an expired access token, and turning every way the
// fetch can fail into a message that says what to do. Pure, so it's tested.

/// Claude Code's OAuth client id. A refresh token can only be redeemed by the
/// client it was issued to, so renewing Claude Code's sign-in needs this one.
public let claudeCodeOAuthClientID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
/// Token endpoints, newest first; the second is the older host for the same service.
public let claudeOAuthTokenURLs = ["https://platform.claude.com/v1/oauth/token",
                                   "https://console.anthropic.com/v1/oauth/token"]
public let claudeUsageURL = "https://api.anthropic.com/api/oauth/usage"
/// Claude Code's keychain item (service name). Its account is the login name.
public let claudeKeychainService = "Claude Code-credentials"

public struct ClaudeOAuth: Equatable {
    public var accessToken: String
    public var refreshToken: String?
    public var expiresAt: Date?
    public var scopes: [String]
    public var subscriptionType: String?

    public init(accessToken: String, refreshToken: String? = nil, expiresAt: Date? = nil,
                scopes: [String] = [], subscriptionType: String? = nil) {
        self.accessToken = accessToken; self.refreshToken = refreshToken
        self.expiresAt = expiresAt; self.scopes = scopes; self.subscriptionType = subscriptionType
    }

    /// Expired, or about to be within `margin`. No expiry recorded counts as fresh.
    public func isExpired(now: Date, margin: TimeInterval = 30) -> Bool {
        expiresAt.map { $0.timeIntervalSince(now) <= margin } ?? false
    }

    /// The usage endpoint needs `user:profile`. Long-lived `claude setup-token`
    /// tokens only carry `user:inference`. No scopes recorded: assume it can.
    public var canReadUsage: Bool { scopes.isEmpty || scopes.contains("user:profile") }
}

public enum CredentialRead: Equatable {
    case found(ClaudeOAuth)
    /// The store exists but holds no Claude sign-in (for example only MCP server logins).
    case noClaudeLogin
    case malformed
}

/// Millisecond timestamps (what Claude Code writes), second timestamps, or ISO 8601.
func parseExpiry(_ v: Any?) -> Date? {
    if let n = v as? NSNumber, !(n === kCFBooleanTrue || n === kCFBooleanFalse) {
        let x = n.doubleValue
        guard x > 0 else { return nil }
        return Date(timeIntervalSince1970: x > 1e11 ? x / 1000 : x)
    }
    if let s = v as? String { return parseISO(s) ?? Double(s).flatMap { parseExpiry(NSNumber(value: $0)) } }
    return nil
}

/// Reads Claude Code's stored credentials (the keychain item or
/// `~/.claude/.credentials.json`): `{"claudeAiOauth": {...}, "mcpOAuth": {...}}`,
/// or the token fields at the top level.
public func parseClaudeCredentials(_ text: String) -> CredentialRead {
    let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !trimmed.isEmpty, let data = trimmed.data(using: .utf8),
          let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else { return .malformed }
    let o = (obj["claudeAiOauth"] as? [String: Any]) ?? obj
    guard let token = o["accessToken"] as? String, !token.isEmpty else { return .noClaudeLogin }
    let scopes: [String]
    if let a = o["scopes"] as? [String] { scopes = a }
    else if let s = o["scopes"] as? String { scopes = s.split(separator: " ").map(String.init) }
    else { scopes = [] }
    return .found(ClaudeOAuth(accessToken: token,
                              refreshToken: (o["refreshToken"] as? String).flatMap { $0.isEmpty ? nil : $0 },
                              expiresAt: parseExpiry(o["expiresAt"]),
                              scopes: scopes,
                              subscriptionType: o["subscriptionType"] as? String))
}

/// A successful answer from the token endpoint.
public struct TokenGrant: Equatable {
    public let accessToken: String
    public let refreshToken: String?
    public let expiresAt: Date?
    public let scopes: [String]?
}

public func parseTokenGrant(_ json: [String: Any], now: Date) -> TokenGrant? {
    guard let at = json["access_token"] as? String, !at.isEmpty else { return nil }
    let expiresIn = (json["expires_in"] as? NSNumber)?.doubleValue
    return TokenGrant(accessToken: at,
                      refreshToken: (json["refresh_token"] as? String).flatMap { $0.isEmpty ? nil : $0 },
                      expiresAt: expiresIn.map { now.addingTimeInterval($0) },
                      scopes: (json["scope"] as? String).map { $0.split(separator: " ").map(String.init) })
}

/// The stored credentials with a renewed token written in, every other field
/// (MCP logins, subscription type, …) kept as it was. nil if it can't be parsed.
public func mergeTokenGrant(into original: String, _ g: TokenGrant) -> String? {
    guard let data = original.data(using: .utf8),
          var obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else { return nil }
    func apply(_ o: inout [String: Any]) {
        o["accessToken"] = g.accessToken
        if let r = g.refreshToken { o["refreshToken"] = r }   // no new one: the old one stays valid
        if let e = g.expiresAt { o["expiresAt"] = NSNumber(value: Int64((e.timeIntervalSince1970 * 1000).rounded())) }
        if let s = g.scopes, !s.isEmpty { o["scopes"] = s }
    }
    if var nested = obj["claudeAiOauth"] as? [String: Any] {
        apply(&nested)
        obj["claudeAiOauth"] = nested
    } else if obj["accessToken"] != nil {
        apply(&obj)
    } else { return nil }
    guard let out = try? JSONSerialization.data(withJSONObject: obj, options: [.withoutEscapingSlashes]) else { return nil }
    return String(decoding: out, as: UTF8.self)
}

/// `"acct"<blob>="name"` from `security find-generic-password -s …` (no `-w`).
public func parseKeychainAccount(_ attributes: String) -> String? {
    regexGroups(#""acct"<blob>="([^"]*)""#, attributes).flatMap { $0.count > 1 && !$0[1].isEmpty ? $0[1] : nil }
}

/// Lowercase hex, for `security add-generic-password -X`, which keeps the
/// secret off the command line (and out of `ps`).
public func hexEncoded(_ s: String) -> String {
    Data(s.utf8).map { String(format: "%02x", $0) }.joined()
}

/// Where the `claude` command is usually installed (native installer, npm, Homebrew, bun).
public func claudeCLICandidates(home: String) -> [String] {
    ["\(home)/.local/bin/claude", "\(home)/.claude/local/claude", "/opt/homebrew/bin/claude",
     "/usr/local/bin/claude", "\(home)/.npm-global/bin/claude", "\(home)/.bun/bin/claude"]
}

// MARK: failures

/// Why the usage meter has no fresh numbers, and what would fix it.
public enum UsageProblem: Error, Equatable {
    /// No Claude Code sign-in anywhere, and no `claude` command found.
    case cliNotInstalled
    /// No Claude Code sign-in (the Claude desktop app keeps its own, which apps can't read).
    case notSignedIn
    /// macOS wouldn't hand over the keychain item (Deny clicked, or the prompt timed out).
    case keychainDenied
    /// The sign-in expired and couldn't be renewed.
    case signInExpired
    /// The token can't read usage (a `claude setup-token` token, for instance).
    case missingScope
    case rateLimited(until: Date)
    case offline
    case server(Int)
    case unexpectedResponse

    /// One line for the menu.
    public var message: String {
        switch self {
        case .cliNotInstalled:    return "Claude Code isn't signed in on this Mac"
        case .notSignedIn:        return "Claude Code isn't signed in"
        case .keychainDenied:     return "Keychain access was denied"
        case .signInExpired:      return "Claude Code's sign-in has expired"
        case .missingScope:       return "This sign-in can't read usage"
        case .rateLimited(let u): return "Anthropic asked to wait, retrying \(clockStr(u))"
        case .offline:            return "Offline, will retry"
        case .server(let c):      return "Anthropic's server answered \(c), will retry"
        case .unexpectedResponse: return "Usage came back in an unknown format"
        }
    }

    /// What to do about it; nil when it fixes itself.
    public var hint: String? {
        switch self {
        case .cliNotInstalled:
            return "The desktop app's sign-in can't be read. Install Claude Code in Terminal, run claude, then /login."
        case .notSignedIn:
            return "Run claude in Terminal and type /login. The desktop app's sign-in can't be read."
        case .keychainDenied:
            return "Click to try again, then choose Always Allow."
        case .signInExpired:
            return "Run claude in Terminal and type /login."
        case .missingScope:
            return "Tokens from claude setup-token can't read usage. Sign in with /login in claude instead."
        case .unexpectedResponse:
            return "The endpoint may have changed. Updating Ephedrine may fix it."
        case .rateLimited, .offline, .server:
            return nil
        }
    }

    /// Needs something from the user (as opposed to clearing up by itself).
    public var needsUser: Bool {
        switch self {
        case .cliNotInstalled, .notSignedIn, .keychainDenied, .signInExpired, .missingScope: return true
        default: return false
        }
    }

    /// Same kind of problem (for logging each one once, not every retry).
    public var kind: String {
        switch self {
        case .rateLimited: return "rateLimited"
        case .server(let c): return "server\(c)"
        default: return String(describing: self)
        }
    }
}

/// Retry-After as seconds or an HTTP date.
public func parseRetryAfter(_ v: String?, now: Date) -> Date? {
    guard let v = v?.trimmingCharacters(in: .whitespaces), !v.isEmpty else { return nil }
    if let s = Double(v) { return now.addingTimeInterval(max(0, s)) }
    let f = DateFormatter()
    f.locale = Locale(identifier: "en_US_POSIX")
    f.timeZone = TimeZone(identifier: "GMT")
    f.dateFormat = "EEE, dd MMM yyyy HH:mm:ss zzz"
    return f.date(from: v)
}

/// The usage endpoint's non-2xx answers (401 is handled by renewing first).
public func usageProblem(status: Int, body: Data?, retryAfter: String?, consecutiveFailures: Int, now: Date) -> UsageProblem {
    switch status {
    case 401: return .signInExpired
    case 403:
        let text = body.map { String(decoding: $0, as: UTF8.self).lowercased() } ?? ""
        return text.contains("scope") || text.contains("permission") || text.isEmpty ? .missingScope : .server(403)
    case 429:
        let fallback = now.addingTimeInterval(rateLimitBackoff(consecutiveFailures))
        let until = parseRetryAfter(retryAfter, now: now).map { max($0, now.addingTimeInterval(60)) } ?? fallback
        return .rateLimited(until: until)
    default: return .server(status)
    }
}

/// 5, 10, 20, then 30 minutes.
func rateLimitBackoff(_ failures: Int) -> TimeInterval {
    min(30 * 60, 5 * 60 * pow(2, Double(max(0, failures))))
}

/// How long to wait before fetching again after `problem`.
public func usageRetryDelay(_ problem: UsageProblem, consecutiveFailures n: Int, now: Date) -> TimeInterval {
    switch problem {
    case .rateLimited(let until): return max(60, until.timeIntervalSince(now))
    case .offline:                return 60
    case .server:                 return min(30 * 60, 60 * pow(2, Double(max(0, n - 1))))
    default:                      return 10 * 60   // needs the user; clicking retries right away
    }
}

// MARK: display

/// "resets in 2h 14m" within a day, "resets Tue 9:00 AM" after.
public func resetPhrase(_ d: Date?, now: Date) -> String? {
    guard let d = d else { return nil }
    let s = Int(d.timeIntervalSince(now).rounded())
    if s <= 0 { return "resetting now" }
    if s >= 24 * 3600 { return "resets \(clockStr(d))" }
    let h = s / 3600, m = (s % 3600 + 59) / 60
    if h == 0 { return "resets in \(max(1, m))m" }
    return m == 60 ? "resets in \(h + 1)h" : (m == 0 ? "resets in \(h)h" : "resets in \(h)h \(m)m")
}

/// "updated just now" / "updated 4m ago" / "updated 2h ago".
public func updatedPhrase(_ d: Date, now: Date) -> String {
    let s = Int(now.timeIntervalSince(d))
    if s < 60 { return "updated just now" }
    if s < 3600 { return "updated \(s / 60)m ago" }
    return "updated \(s / 3600)h ago"
}

/// What the menu bar shows next to the icon.
public enum MenuBarUsage: String, CaseIterable {
    case off, session, highest
    public var label: String {
        switch self {
        case .off: return "Off"
        case .session: return "Session limit"
        case .highest: return "Highest limit"
        }
    }

    /// "42%", or nil when there's nothing to show.
    public func badge(_ limits: [UsageLimit]) -> String? {
        let pick: UsageLimit?
        switch self {
        case .off: return nil
        case .session: pick = limits.first { $0.key == "session" || $0.key == "five_hour" } ?? limits.first
        case .highest: pick = limits.max { $0.percent < $1.percent }
        }
        return pick.map { String(format: "%.0f%%", $0.percent) }
    }
}
