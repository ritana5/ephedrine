import Testing
import Foundation
@testable import EphedrineCore

private func obj(_ s: String) -> [String: Any] {
    (try? JSONSerialization.jsonObject(with: Data(s.utf8))) as? [String: Any] ?? [:]
}

// ── Reading the stored sign-in ──

@Test func credentialsNestedUnderClaudeAiOauth() {
    let r = parseClaudeCredentials("""
    {"claudeAiOauth":{"accessToken":"at","refreshToken":"rt","expiresAt":1767225600000,
     "scopes":["user:inference","user:profile"],"subscriptionType":"max"},"mcpOAuth":{"x":{}}}
    """)
    guard case .found(let o) = r else { Issue.record("not found: \(r)"); return }
    #expect(o.accessToken == "at")
    #expect(o.refreshToken == "rt")
    #expect(o.expiresAt == Date(timeIntervalSince1970: 1767225600))
    #expect(o.subscriptionType == "max")
    #expect(o.canReadUsage)
}

@Test func credentialsWithOnlyMCPLoginsHaveNoClaudeLogin() {
    // What a Mac signed in only through the desktop app holds (2026-11-12).
    #expect(parseClaudeCredentials(#"{"mcpOAuth":{"server|abc":{"accessToken":"x"}}}"#) == .noClaudeLogin)
}

@Test func credentialsMalformedOrEmpty() {
    #expect(parseClaudeCredentials("") == .malformed)
    #expect(parseClaudeCredentials("not json") == .malformed)
    #expect(parseClaudeCredentials(#"{"claudeAiOauth":{"accessToken":""}}"#) == .noClaudeLogin)
}

@Test func credentialsTopLevelAndSecondExpiry() {
    guard case .found(let o) = parseClaudeCredentials(#"{"accessToken":"a","expiresAt":1767225600,"scopes":"user:inference"}"#) else {
        Issue.record("not found"); return
    }
    #expect(o.expiresAt == Date(timeIntervalSince1970: 1767225600))
    #expect(o.scopes == ["user:inference"])
    #expect(!o.canReadUsage)   // a setup-token style token
}

@Test func expiryWithMargin() {
    let now = Date(timeIntervalSince1970: 1000)
    #expect(ClaudeOAuth(accessToken: "a", expiresAt: now.addingTimeInterval(10)).isExpired(now: now))
    #expect(!ClaudeOAuth(accessToken: "a", expiresAt: now.addingTimeInterval(3600)).isExpired(now: now))
    #expect(!ClaudeOAuth(accessToken: "a").isExpired(now: now))
}

// ── Renewing ──

@Test func tokenGrantParses() {
    let now = Date(timeIntervalSince1970: 1000)
    let g = parseTokenGrant(obj(#"{"access_token":"new","refresh_token":"r2","expires_in":28800,"scope":"user:inference user:profile"}"#), now: now)
    #expect(g == TokenGrant(accessToken: "new", refreshToken: "r2", expiresAt: now.addingTimeInterval(28800),
                            scopes: ["user:inference", "user:profile"]))
    #expect(parseTokenGrant(obj(#"{"error":"invalid_grant"}"#), now: now) == nil)
}

@Test func mergeKeepsEveryOtherField() {
    let original = #"{"claudeAiOauth":{"accessToken":"old","refreshToken":"r1","expiresAt":1,"scopes":["user:profile"],"subscriptionType":"pro"},"mcpOAuth":{"srv":{"accessToken":"mcp","url":"https://x/y"}}}"#
    let g = TokenGrant(accessToken: "new", refreshToken: "r2", expiresAt: Date(timeIntervalSince1970: 2000), scopes: nil)
    guard let merged = mergeTokenGrant(into: original, g) else { Issue.record("no merge"); return }
    let m = obj(merged)
    let c = m["claudeAiOauth"] as? [String: Any]
    #expect(c?["accessToken"] as? String == "new")
    #expect(c?["refreshToken"] as? String == "r2")
    #expect((c?["expiresAt"] as? NSNumber)?.int64Value == 2_000_000)
    #expect(c?["subscriptionType"] as? String == "pro")
    #expect(c?["scopes"] as? [String] == ["user:profile"])
    #expect(((m["mcpOAuth"] as? [String: Any])?["srv"] as? [String: Any])?["accessToken"] as? String == "mcp")
    #expect(!merged.contains(#"\/"#))   // slashes left alone, as Claude Code writes them
    guard case .found(let o) = parseClaudeCredentials(merged) else { Issue.record("unreadable"); return }
    #expect(o.accessToken == "new")
}

@Test func mergeWithoutNewRefreshTokenKeepsTheOld() {
    let g = TokenGrant(accessToken: "new", refreshToken: nil, expiresAt: nil, scopes: nil)
    let merged = mergeTokenGrant(into: #"{"claudeAiOauth":{"accessToken":"old","refreshToken":"r1"}}"#, g)
    #expect((obj(merged ?? "")["claudeAiOauth"] as? [String: Any])?["refreshToken"] as? String == "r1")
    #expect(mergeTokenGrant(into: #"{"mcpOAuth":{}}"#, g) == nil)
}

@Test func keychainAccountAndHex() {
    let attrs = """
    keychain: "/Users/me/Library/Keychains/login.keychain-db"
        "acct"<blob>="me"
        "svce"<blob>="Claude Code-credentials"
    """
    #expect(parseKeychainAccount(attrs) == "me")
    #expect(parseKeychainAccount(#""acct"<blob>=<NULL>"#) == nil)
    #expect(hexEncoded(#"{"a":1}"#) == "7b2261223a317d")
}

// ── Failures and backoff ──

@Test func usageProblemsByStatus() {
    let now = Date(timeIntervalSince1970: 0)
    #expect(usageProblem(status: 401, body: nil, retryAfter: nil, consecutiveFailures: 0, now: now) == .signInExpired)
    #expect(usageProblem(status: 403, body: Data(#"{"error":{"message":"OAuth token does not meet scope requirement user:profile"}}"#.utf8),
                         retryAfter: nil, consecutiveFailures: 0, now: now) == .missingScope)
    #expect(usageProblem(status: 500, body: nil, retryAfter: nil, consecutiveFailures: 0, now: now) == .server(500))
    #expect(usageProblem(status: 429, body: nil, retryAfter: "120", consecutiveFailures: 0, now: now)
            == .rateLimited(until: now.addingTimeInterval(120)))
    // No Retry-After: 5 minutes, doubling.
    #expect(usageProblem(status: 429, body: nil, retryAfter: nil, consecutiveFailures: 1, now: now)
            == .rateLimited(until: now.addingTimeInterval(600)))
    // A tiny Retry-After still waits at least a minute.
    #expect(usageProblem(status: 429, body: nil, retryAfter: "0", consecutiveFailures: 0, now: now)
            == .rateLimited(until: now.addingTimeInterval(60)))
}

@Test func retryAfterHTTPDate() {
    let now = Date(timeIntervalSince1970: 0)
    #expect(parseRetryAfter("Thu, 01 Jan 1970 00:02:00 GMT", now: now) == Date(timeIntervalSince1970: 120))
    #expect(parseRetryAfter(nil, now: now) == nil)
    #expect(parseRetryAfter("soon", now: now) == nil)
}

@Test func retryDelays() {
    let now = Date(timeIntervalSince1970: 0)
    #expect(usageRetryDelay(.offline, consecutiveFailures: 3, now: now) == 60)
    #expect(usageRetryDelay(.server(502), consecutiveFailures: 1, now: now) == 60)
    #expect(usageRetryDelay(.server(502), consecutiveFailures: 3, now: now) == 240)
    #expect(usageRetryDelay(.server(502), consecutiveFailures: 20, now: now) == 1800)
    #expect(usageRetryDelay(.rateLimited(until: now.addingTimeInterval(900)), consecutiveFailures: 1, now: now) == 900)
    #expect(usageRetryDelay(.notSignedIn, consecutiveFailures: 1, now: now) == 600)
}

@Test func problemsThatNeedTheUserSayWhatToDo() {
    for p: UsageProblem in [.cliNotInstalled, .notSignedIn, .keychainDenied, .signInExpired, .missingScope] {
        #expect(p.needsUser)
        #expect(p.hint != nil)
    }
    #expect(!UsageProblem.offline.needsUser)
    #expect(UsageProblem.rateLimited(until: Date()).kind == UsageProblem.rateLimited(until: .distantFuture).kind)
}

// ── Display ──

@Test func resetPhrases() {
    let now = Date(timeIntervalSince1970: 1_000_000)
    #expect(resetPhrase(nil, now: now) == nil)
    #expect(resetPhrase(now.addingTimeInterval(-5), now: now) == "resetting now")
    #expect(resetPhrase(now.addingTimeInterval(30), now: now) == "resets in 1m")
    #expect(resetPhrase(now.addingTimeInterval(45 * 60), now: now) == "resets in 45m")
    #expect(resetPhrase(now.addingTimeInterval(2 * 3600 + 14 * 60), now: now) == "resets in 2h 14m")
    #expect(resetPhrase(now.addingTimeInterval(3 * 3600), now: now) == "resets in 3h")
    #expect(resetPhrase(now.addingTimeInterval(3 * 3600 - 10), now: now) == "resets in 3h")
    #expect(resetPhrase(now.addingTimeInterval(3 * 86400), now: now)?.hasPrefix("resets ") == true)
    #expect(resetPhrase(now.addingTimeInterval(3 * 86400), now: now)?.contains(" in ") == false)
}

@Test func updatedPhrases() {
    let now = Date(timeIntervalSince1970: 10_000)
    #expect(updatedPhrase(now.addingTimeInterval(-20), now: now) == "updated just now")
    #expect(updatedPhrase(now.addingTimeInterval(-250), now: now) == "updated 4m ago")
    #expect(updatedPhrase(now.addingTimeInterval(-7300), now: now) == "updated 2h ago")
}

@Test func menuBarBadge() {
    let limits = [UsageLimit(key: "session", label: "Session (5h)", percent: 38.4, resetsAt: nil),
                  UsageLimit(key: "weekly_all", label: "Weekly", percent: 71.6, resetsAt: nil)]
    #expect(MenuBarUsage.off.badge(limits) == nil)
    #expect(MenuBarUsage.session.badge(limits) == "38%")
    #expect(MenuBarUsage.highest.badge(limits) == "72%")
    #expect(MenuBarUsage.session.badge([]) == nil)
    #expect(MenuBarUsage.session.badge([UsageLimit(key: "five_hour", label: "S", percent: 5, resetsAt: nil)]) == "5%")
}

@Test func menuBarUsageSettingPersists() {
    let d = UserDefaults(suiteName: "ephedrine.test.\(UUID().uuidString)")!
    let s = AppSettings(defaults: d)
    #expect(s.menuBarUsage == .off)
    s.menuBarUsage = .highest
    #expect(AppSettings(defaults: d).menuBarUsage == .highest)
}
