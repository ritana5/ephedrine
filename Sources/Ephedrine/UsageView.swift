import Cocoa
import EphedrineCore

/// Custom menu row for Claude usage: one horizontal bar per limit (session,
/// weekly, per-model like "Fable only"). Clicking refreshes in place WITHOUT
/// closing the menu (view-based items don't auto-dismiss), and it redraws
/// live when the async fetch returns.
final class UsageView: NSView {
    struct Row {
        let label: String     // "Session (5h)"
        let percent: Double
        let detail: String    // "38% · resets 1:10 AM"
        let level: UsageLevel
    }

    var onClick: (() -> Void)?
    private var rows: [Row] = []
    private var status = ""
    private var message: String? = "Loading…"
    private var hint: String?
    private var hovered = false

    private static let topPad: CGFloat = 4
    private static let headerH: CGFloat = 22
    private static let rowLabelH: CGFloat = 15
    private static let rowGap: CGFloat = 9
    private static let rowH: CGFloat = 25

    init() {
        super.init(frame: NSRect(x: 0, y: 0, width: MenuMetrics.width, height: Self.topPad + Self.headerH + 23))
        setAccessibilityRole(.button)
    }
    required init?(coder: NSCoder) { fatalError() }

    override var isFlipped: Bool { true }

    private static var textWidth: CGFloat { MenuMetrics.width - 2 * MenuMetrics.inset }
    private static let hintFont = NSFont.systemFont(ofSize: 11)
    private static let messageFont = NSFont.systemFont(ofSize: 12)

    private static func wrappedHeight(_ s: String?, _ font: NSFont) -> CGFloat {
        guard let s = s, !s.isEmpty else { return 0 }
        return ceil(NSAttributedString(string: s, attributes: [.font: font])
            .boundingRect(with: NSSize(width: textWidth, height: 1000), options: [.usesLineFragmentOrigin]).height)
    }

    private func layoutHeight() -> CGFloat {
        var h = Self.topPad + Self.headerH
        if let m = message {
            h += 1 + Self.wrappedHeight(m, Self.messageFont)
        } else if !rows.isEmpty {
            h += 5 + CGFloat(rows.count) * Self.rowH + CGFloat(rows.count - 1) * Self.rowGap
        }
        if let hnt = hint { h += 4 + Self.wrappedHeight(hnt, Self.hintFont) }
        return h + 6
    }

    func update(rows: [Row], status: String, message: String?, hint: String? = nil) {
        self.rows = rows; self.status = status; self.message = message; self.hint = hint
        let h = layoutHeight()
        if frame.height != h { setFrameSize(NSSize(width: MenuMetrics.width, height: h)) }
        let body = message ?? rows.map { "\($0.label) \($0.detail)" }.joined(separator: ", ")
        setAccessibilityLabel([body, hint].compactMap { $0 }.joined(separator: ". "))
        needsDisplay = true
    }

    private func text(_ s: String, size: CGFloat, weight: NSFont.Weight = .regular, color: NSColor) -> NSAttributedString {
        NSAttributedString(string: s, attributes: [
            .font: NSFont.monospacedDigitSystemFont(ofSize: size, weight: weight),
            .foregroundColor: color,
        ])
    }

    private func barColor(_ level: UsageLevel) -> NSColor {
        switch level {
        case .normal:   return claudeOrange
        case .warning:  return menuWarningColor
        case .critical: return .systemRed
        }
    }

    override func draw(_ dirtyRect: NSRect) {
        super.draw(dirtyRect)
        if hovered {
            NSColor.selectedContentBackgroundColor.withAlphaComponent(0.18).setFill()
            NSBezierPath(roundedRect: bounds.insetBy(dx: 5, dy: 1), xRadius: 5, yRadius: 5).fill()
        }
        let x = MenuMetrics.inset, w = bounds.width - 2 * MenuMetrics.inset

        // header: "Claude usage" ………… "↻ click to refresh"
        let hy = Self.topPad + Self.headerH / 2
        let title = text("Claude usage", size: 12, weight: .semibold, color: .labelColor)
        title.draw(at: NSPoint(x: x, y: hy - title.size().height / 2))
        let st = text(status, size: 11, color: .tertiaryLabelColor)
        var sx = x + w - st.size().width
        st.draw(at: NSPoint(x: sx, y: hy - st.size().height / 2))
        let cfg = NSImage.SymbolConfiguration(pointSize: 10, weight: .regular)
            .applying(NSImage.SymbolConfiguration(paletteColors: [.tertiaryLabelColor]))
        if !status.isEmpty, let arrow = NSImage(systemSymbolName: "arrow.clockwise", accessibilityDescription: nil)?.withSymbolConfiguration(cfg) {
            sx -= arrow.size.width + 4
            arrow.draw(in: NSRect(x: sx, y: hy - arrow.size.height / 2, width: arrow.size.width, height: arrow.size.height),
                       from: .zero, operation: .sourceOver, fraction: 1, respectFlipped: true, hints: nil)
        }

        let top0 = Self.topPad + Self.headerH
        func wrapped(_ s: String, _ font: NSFont, _ color: NSColor, at y: CGFloat) -> CGFloat {
            let a = NSAttributedString(string: s, attributes: [.font: font, .foregroundColor: color])
            let r = NSRect(x: x, y: y, width: w, height: Self.wrappedHeight(s, font))
            a.draw(with: r, options: [.usesLineFragmentOrigin])
            return r.maxY
        }
        if let m = message {
            let bottom = wrapped(m, Self.messageFont, .secondaryLabelColor, at: top0 + 1)
            if let hnt = hint { _ = wrapped(hnt, Self.hintFont, .tertiaryLabelColor, at: bottom + 4) }
            return
        }
        for (i, r) in rows.enumerated() {
            let top = top0 + 5 + CGFloat(i) * (Self.rowH + Self.rowGap)
            text(r.label, size: 12, color: .labelColor).draw(at: NSPoint(x: x, y: top))
            let d = text(r.detail, size: 11, color: .secondaryLabelColor)
            d.draw(at: NSPoint(x: x + w - d.size().width, y: top + 1))

            let track = NSRect(x: x, y: top + Self.rowLabelH + 5, width: w, height: 5)
            NSColor.quaternaryLabelColor.setFill()
            NSBezierPath(roundedRect: track, xRadius: 2.5, yRadius: 2.5).fill()
            let frac = CGFloat(min(max(r.percent, 0), 100) / 100)
            if frac > 0 {
                var fill = track; fill.size.width = max(track.height, track.width * frac)
                barColor(r.level).withAlphaComponent(hint == nil ? 1 : 0.55).setFill()   // faded while stale
                NSBezierPath(roundedRect: fill, xRadius: 2.5, yRadius: 2.5).fill()
            }
        }
        if let hnt = hint, !rows.isEmpty {
            let y = top0 + 5 + CGFloat(rows.count) * Self.rowH + CGFloat(rows.count - 1) * Self.rowGap + 4
            _ = wrapped(hnt, Self.hintFont, .tertiaryLabelColor, at: y)
        }
    }

    override func updateTrackingAreas() {
        super.updateTrackingAreas()
        trackingAreas.forEach(removeTrackingArea)
        addTrackingArea(NSTrackingArea(rect: bounds, options: [.mouseEnteredAndExited, .activeAlways], owner: self))
    }
    override func mouseEntered(with e: NSEvent) { hovered = true; needsDisplay = true }
    override func mouseExited(with e: NSEvent) { hovered = false; needsDisplay = true }
    override func mouseUp(with e: NSEvent) { onClick?() }
    override func accessibilityPerformPress() -> Bool { onClick?(); return true }
}
