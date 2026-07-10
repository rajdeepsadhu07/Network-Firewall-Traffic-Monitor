"""
URL Phishing Detection System
Main GUI Application — Tkinter dark-theme UI
"""

import threading
import tkinter as tk
from tkinter import font
import urllib.parse
import tldextract

from detector import analyze_url

# ── Color palette ─────────────────────────────────────────────────────────────
BG_DARK    = "#0d1117"   # GitHub-dark background
BG_CARD    = "#161b22"   # card/panel surface
BG_INPUT   = "#21262d"   # input field background
BG_HOVER   = "#30363d"   # hover state
BG_TAG     = "#1c2128"   # badge / tag background
FG_PRIMARY = "#5d96c8"   # primary text
FG_MUTED   = "#7d8590"   # secondary / hint text
FG_ACCENT  = "#7c6af7"   # purple accent (buttons, links)
BORDER     = "#30363d"   # dividers / borders

CLR_SAFE       = "#3fb950"   # green
CLR_SUSPICIOUS = "#d29922"   # amber
CLR_DANGEROUS  = "#f85149"   # red
CLR_UNKNOWN    = "#6391d1"   # grey


class PhishingDetectorApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("URL Phishing Detector  |  Security Tool")
        self.geometry("900x720")
        self.minsize(780, 600)
        self.configure(bg=BG_DARK)
        self.resizable(True, True)

        self._history = []
        self._anim_after_id = None

        self._setup_fonts()
        self._build_ui()
        self._bind_events()

    # ── Fonts ─────────────────────────────────────────────────────────────────
    def _setup_fonts(self):
        self.f_title    = font.Font(family="Helvetica", size=22, weight="bold")
        self.f_subtitle = font.Font(family="Helvetica", size=10)
        self.f_label    = font.Font(family="Helvetica", size=11, weight="bold")
        self.f_normal   = font.Font(family="Helvetica", size=10)
        self.f_small    = font.Font(family="Helvetica", size=9)
        self.f_score    = font.Font(family="Helvetica", size=34, weight="bold")
        self.f_verdict  = font.Font(family="Helvetica", size=13, weight="bold")
        self.f_mono     = font.Font(family="Courier", size=9)
        self.f_tag      = font.Font(family="Helvetica", size=8, weight="bold")

    # ── UI Layout ─────────────────────────────────────────────────────────────
    def _build_ui(self):
        # ── Top banner ────────────────────────────────────────────────────────
        banner = tk.Frame(self, bg="#0d1117", pady=0)
        banner.pack(fill="x")

        # Accent top-border stripe
        tk.Frame(banner, bg=FG_ACCENT, height=3).pack(fill="x")

        header = tk.Frame(banner, bg=BG_DARK, pady=18)
        header.pack(fill="x", padx=32)

        # Left: icon + title stack
        title_col = tk.Frame(header, bg=BG_DARK)
        title_col.pack(side="left")

        title_row = tk.Frame(title_col, bg=BG_DARK)
        title_row.pack(anchor="w")

        tk.Label(title_row, text="🛡", font=font.Font(size=20),
                 bg=BG_DARK, fg=FG_ACCENT).pack(side="left", padx=(0, 8))
        tk.Label(title_row, text="URL Phishing Detector",
                 font=self.f_title, fg=FG_PRIMARY, bg=BG_DARK).pack(side="left")

        # Version tag
        tag = tk.Label(title_row, text=" v1.0 ",
                       font=self.f_tag, fg=FG_ACCENT, bg=BG_TAG,
                       relief="flat", padx=4, pady=2)
        tag.pack(side="left", padx=(10, 0), pady=(4, 0))

        tk.Label(title_col,
                 text="Heuristic-based phishing detection · 20+ URL pattern signals · Real-time scoring",
                 font=self.f_subtitle, fg=FG_MUTED, bg=BG_DARK).pack(anchor="w", pady=(3, 0))

        # Right: stats pills
        stats_col = tk.Frame(header, bg=BG_DARK)
        stats_col.pack(side="right")
        for text, val in [("Signals", "20+"), ("Accuracy", "Rule-based"), ("Speed", "< 1s")]:
            pill = tk.Frame(stats_col, bg=BG_CARD, padx=12, pady=6)
            pill.pack(side="left", padx=4)
            tk.Label(pill, text=val, font=self.f_label,
                     fg=FG_ACCENT, bg=BG_CARD).pack()
            tk.Label(pill, text=text, font=self.f_small,
                     fg=FG_MUTED, bg=BG_CARD).pack()

        # ── Divider ───────────────────────────────────────────────────────────
        tk.Frame(self, bg=BORDER, height=1).pack(fill="x")

        # ── Input card ───────────────────────────────────────────────────────
        input_card = tk.Frame(self, bg=BG_CARD, pady=16, padx=28)
        input_card.pack(fill="x", padx=28, pady=14)

        # Section label with left accent bar
        lbl_row = tk.Frame(input_card, bg=BG_CARD)
        lbl_row.pack(anchor="w", pady=(0, 8))
        tk.Frame(lbl_row, bg=FG_ACCENT, width=3, height=18).pack(side="left", padx=(0, 8))
        tk.Label(lbl_row, text="Enter URL to Analyze",
                 font=self.f_label, fg=FG_PRIMARY, bg=BG_CARD).pack(side="left")

        input_row = tk.Frame(input_card, bg=BG_CARD)
        input_row.pack(fill="x")

        self.url_var = tk.StringVar()
        self.url_entry = tk.Entry(
            input_row, textvariable=self.url_var,
            font=font.Font(family="Courier", size=11),
            bg=BG_INPUT, fg=FG_PRIMARY,
            insertbackground=FG_PRIMARY, relief="flat",
            bd=0, highlightthickness=2,
            highlightcolor=FG_ACCENT, highlightbackground=BORDER,
        )
        self.url_entry.pack(side="left", fill="x", expand=True, ipady=11, padx=(0, 10))
        self.url_entry.insert(0, "https://")

        self.analyze_btn = tk.Button(
            input_row, text="  🔍  Analyze  ",
            font=self.f_label, bg=FG_ACCENT, fg="white",
            relief="flat", bd=0, cursor="hand2",
            activebackground="#6355e8", activeforeground="white",
            command=self._on_analyze,
        )
        self.analyze_btn.pack(side="left", ipady=11, ipadx=8)

        # Example links row
        examples_row = tk.Frame(input_card, bg=BG_CARD)
        examples_row.pack(anchor="w", pady=(8, 0))
        tk.Label(examples_row, text="Quick test:", font=self.f_small,
                 fg=FG_MUTED, bg=BG_CARD).pack(side="left", padx=(0, 6))
        examples = [
            ("✅  github.com",          "https://github.com"),
            ("🚨  Phishing sample",     "http://secure-paypal-login.verify-account.tk/update?user=admin"),
            ("⚠️  URL shortener",        "http://bit.ly/3xAbc12"),
            ("🚨  IP-based",            "http://192.168.1.1/login"),
        ]
        for label, url in examples:
            lbl = tk.Label(examples_row, text=label, font=self.f_small,
                           fg=FG_ACCENT, bg=BG_CARD, cursor="hand2")
            lbl.pack(side="left", padx=(0, 12))
            lbl.bind("<Button-1>", lambda e, u=url: self._paste_example(u))
            lbl.bind("<Enter>", lambda e, w=lbl: w.configure(fg=FG_PRIMARY))
            lbl.bind("<Leave>", lambda e, w=lbl: w.configure(fg=FG_ACCENT))

        # ── Results area ─────────────────────────────────────────────────────
        results_frame = tk.Frame(self, bg=BG_DARK)
        results_frame.pack(fill="both", expand=True, padx=28, pady=(0, 14))

        # Left: score + verdict
        left_panel = tk.Frame(results_frame, bg=BG_CARD, padx=18, pady=18, width=240)
        left_panel.pack(side="left", fill="y", padx=(0, 10))
        left_panel.pack_propagate(False)
        self._build_score_panel(left_panel)

        # Right: breakdown + history tabs
        right_panel = tk.Frame(results_frame, bg=BG_DARK)
        right_panel.pack(side="left", fill="both", expand=True)
        self._build_right_panel(right_panel)

        # ── Status bar ───────────────────────────────────────────────────────
        statusbar_wrap = tk.Frame(self, bg=BG_CARD, pady=6)
        statusbar_wrap.pack(fill="x", side="bottom")
        tk.Frame(statusbar_wrap, bg=BORDER, height=1).pack(fill="x")
        self.status_var = tk.StringVar(value="Ready — enter a URL above and press Analyze or hit Enter.")
        tk.Label(
            statusbar_wrap, textvariable=self.status_var,
            font=self.f_small, fg=FG_MUTED, bg=BG_CARD, anchor="w"
        ).pack(fill="x", padx=16, pady=(4, 0))

    def _build_score_panel(self, parent):
        # Section header
        hdr = tk.Frame(parent, bg=BG_CARD)
        hdr.pack(fill="x", pady=(0, 8))
        tk.Frame(hdr, bg=FG_ACCENT, width=3, height=14).pack(side="left", padx=(0, 6))
        tk.Label(hdr, text="Risk Score", font=self.f_label,
                 fg=FG_MUTED, bg=BG_CARD).pack(side="left")

        # Circular score ring canvas
        self.score_canvas = tk.Canvas(
            parent, width=156, height=156,
            bg=BG_CARD, highlightthickness=0
        )
        self.score_canvas.pack(pady=(0, 4))
        self._draw_score_ring(0, CLR_UNKNOWN)

        # Score number
        self.score_label = tk.Label(parent, text="—", font=self.f_score,
                                    fg=FG_MUTED, bg=BG_CARD)
        self.score_label.pack()

        # Verdict with coloured pill background
        self.verdict_frame = tk.Frame(parent, bg=BG_CARD)
        self.verdict_frame.pack(pady=(4, 10))
        self.verdict_label = tk.Label(
            self.verdict_frame, text="  AWAITING URL  ",
            font=self.f_verdict, fg=FG_MUTED, bg=BG_INPUT,
            padx=10, pady=4, relief="flat"
        )
        self.verdict_label.pack()

        # Thin score bar (visual progress under verdict)
        self.bar_canvas = tk.Canvas(parent, height=6, bg=BG_CARD,
                                    highlightthickness=0)
        self.bar_canvas.pack(fill="x", pady=(0, 10))

        tk.Frame(parent, bg=BORDER, height=1).pack(fill="x", pady=(0, 8))

        # URL detail rows
        detail_hdr = tk.Frame(parent, bg=BG_CARD)
        detail_hdr.pack(fill="x", pady=(0, 6))
        tk.Frame(detail_hdr, bg=FG_ACCENT, width=3, height=14).pack(side="left", padx=(0, 6))
        tk.Label(detail_hdr, text="URL Details", font=self.f_label,
                 fg=FG_MUTED, bg=BG_CARD).pack(side="left")

        self.detail_frame = tk.Frame(parent, bg=BG_CARD)
        self.detail_frame.pack(fill="x")
        self._detail_rows = {}
        for key, label in [
            ("scheme", "Protocol"),
            ("domain", "Domain"),
            ("length", "Length"),
            ("tld",    "TLD"),
        ]:
            row = tk.Frame(self.detail_frame, bg=BG_INPUT, pady=4, padx=8)
            row.pack(fill="x", pady=2)
            tk.Label(row, text=label, font=self.f_small,
                     fg=FG_MUTED, bg=BG_INPUT, width=9, anchor="w").pack(side="left")
            val_lbl = tk.Label(row, text="—", font=self.f_small,
                               fg=FG_PRIMARY, bg=BG_INPUT, anchor="w")
            val_lbl.pack(side="left", fill="x", expand=True)
            self._detail_rows[key] = val_lbl

    def _build_right_panel(self, parent):
        # Tab strip
        tab_bar = tk.Frame(parent, bg=BG_DARK)
        tab_bar.pack(fill="x")

        self._tab_contents = {}
        self._tab_btns = {}
        self._active_tab = tk.StringVar(value="breakdown")

        for tab_id, tab_label in [("breakdown", "📊  Risk Breakdown"), ("history", "🕒  Scan History")]:
            is_active = tab_id == "breakdown"
            btn = tk.Button(
                tab_bar, text=tab_label,
                font=self.f_label, relief="flat", bd=0, cursor="hand2",
                bg=BG_CARD if is_active else BG_DARK,
                fg=FG_PRIMARY if is_active else FG_MUTED,
                activebackground=BG_CARD, activeforeground=FG_PRIMARY,
                padx=18, pady=10,
                command=lambda t=tab_id: self._switch_tab(t),
            )
            btn.pack(side="left")
            self._tab_btns[tab_id] = btn

        # Active-tab underline indicator
        self._tab_indicator = tk.Frame(tab_bar, bg=FG_ACCENT, height=2)
        # placed dynamically in _switch_tab

        content_area = tk.Frame(parent, bg=BG_CARD)
        content_area.pack(fill="both", expand=True)

        # Breakdown tab
        bd_frame = tk.Frame(content_area, bg=BG_CARD)
        self._tab_contents["breakdown"] = bd_frame
        self._build_breakdown_tab(bd_frame)

        # History tab
        hist_frame = tk.Frame(content_area, bg=BG_CARD)
        self._tab_contents["history"] = hist_frame
        self._build_history_tab(hist_frame)

        # Show breakdown by default
        bd_frame.pack(fill="both", expand=True)

    def _build_breakdown_tab(self, parent):
        header = tk.Frame(parent, bg=BG_CARD, padx=16, pady=12)
        header.pack(fill="x")
        tk.Label(header, text="Risk Factors Detected", font=self.f_label,
                 fg=FG_PRIMARY, bg=BG_CARD).pack(side="left")
        self.breakdown_count = tk.Label(header, text="", font=self.f_tag,
                                        fg=FG_ACCENT, bg=BG_TAG,
                                        padx=6, pady=2)
        self.breakdown_count.pack(side="left", padx=8)

        tk.Frame(parent, bg=BORDER, height=1).pack(fill="x")

        # Scrollable list
        scroll_frame = tk.Frame(parent, bg=BG_CARD)
        scroll_frame.pack(fill="both", expand=True)

        self.breakdown_canvas = tk.Canvas(scroll_frame, bg=BG_CARD,
                                          highlightthickness=0)
        scrollbar = tk.Scrollbar(scroll_frame, orient="vertical",
                                  command=self.breakdown_canvas.yview)
        self.breakdown_inner = tk.Frame(self.breakdown_canvas, bg=BG_CARD)

        self.breakdown_inner.bind(
            "<Configure>",
            lambda e: self.breakdown_canvas.configure(
                scrollregion=self.breakdown_canvas.bbox("all"))
        )

        self.breakdown_canvas.create_window((0, 0), window=self.breakdown_inner,
                                             anchor="nw")
        self.breakdown_canvas.configure(yscrollcommand=scrollbar.set)

        self.breakdown_canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Placeholder
        self._breakdown_placeholder = tk.Label(
            self.breakdown_inner,
            text="No analysis yet.\nEnter a URL and click Analyze.",
            font=self.f_normal, fg=FG_MUTED, bg=BG_CARD, justify="center"
        )
        self._breakdown_placeholder.pack(pady=40)

    def _build_history_tab(self, parent):
        header = tk.Frame(parent, bg=BG_CARD, padx=16, pady=12)
        header.pack(fill="x")
        tk.Label(header, text="Recent Scans", font=self.f_label,
                 fg=FG_PRIMARY, bg=BG_CARD).pack(side="left")
        tk.Button(
            header, text="Clear", font=self.f_small,
            bg=BG_INPUT, fg=FG_MUTED, relief="flat", cursor="hand2",
            activebackground=BG_HOVER, activeforeground=FG_PRIMARY,
            command=self._clear_history, padx=8
        ).pack(side="right")

        tk.Frame(parent, bg=BORDER, height=1).pack(fill="x")

        self.history_frame = tk.Frame(parent, bg=BG_CARD)
        self.history_frame.pack(fill="both", expand=True, padx=16, pady=8)

        self._history_placeholder = tk.Label(
            self.history_frame,
            text="No scans yet.",
            font=self.f_normal, fg=FG_MUTED, bg=BG_CARD
        )
        self._history_placeholder.pack(pady=40)

    # ── Tab switching ─────────────────────────────────────────────────────────
    def _switch_tab(self, tab_id: str):
        for tid, frame in self._tab_contents.items():
            frame.pack_forget()
        self._tab_contents[tab_id].pack(fill="both", expand=True)
        self._active_tab.set(tab_id)
        for tid, btn in self._tab_btns.items():
            if tid == tab_id:
                btn.configure(bg=BG_CARD, fg=FG_PRIMARY)
            else:
                btn.configure(bg=BG_DARK, fg=FG_MUTED)

    # ── Events ────────────────────────────────────────────────────────────────
    def _bind_events(self):
        self.url_entry.bind("<Return>", lambda e: self._on_analyze())
        self.url_entry.bind("<FocusIn>", self._on_entry_focus)

    def _on_entry_focus(self, event):
        if self.url_var.get() == "https://":
            self.url_entry.icursor("end")

    def _paste_example(self, url: str):
        self.url_var.set(url)
        self.url_entry.icursor("end")
        self._on_analyze()

    # ── Analysis ──────────────────────────────────────────────────────────────
    def _on_analyze(self):
        url = self.url_var.get().strip()
        if not url or url == "https://":
            self._flash_entry()
            return

        self.analyze_btn.configure(text="  ⏳  Analyzing…  ", state="disabled",
                                    bg="#4a3fa0")
        self.status_var.set(f"🔍  Analyzing: {url[:80]}…")
        self.update_idletasks()

        thread = threading.Thread(target=self._run_analysis, args=(url,), daemon=True)
        thread.start()

    def _run_analysis(self, url: str):
        result = analyze_url(url)
        self.after(0, lambda: self._display_result(result))

    def _display_result(self, result: dict):
        self.analyze_btn.configure(text="  🔍  Analyze  ", state="normal", bg=FG_ACCENT)

        if result["error"]:
            self.status_var.set(f"⚠  Error: {result['error']}")
            return

        score     = result["score"]
        risk      = result["risk_level"]
        color     = result["color"]
        emoji     = result["emoji"]
        features  = result["features"]
        breakdown = result["breakdown"]
        safe_sig  = result["safe_signals"]

        # Score ring + progress bar animation
        self._animate_score(0, score, color)

        # Verdict pill
        self.verdict_label.configure(
            text=f"  {emoji}  {risk}  ",
            fg="white", bg=color
        )

        # URL detail rows
        parsed = urllib.parse.urlparse(result["url"] if "://" in result["url"]
                                       else "http://" + result["url"])
        ext = tldextract.extract(result["url"])
        self._detail_rows["scheme"].configure(
            text=parsed.scheme.upper(),
            fg=CLR_SAFE if parsed.scheme == "https" else CLR_DANGEROUS
        )
        self._detail_rows["domain"].configure(
            text=(ext.registered_domain or ext.domain or "—")[:22],
            fg=FG_PRIMARY
        )
        self._detail_rows["length"].configure(
            text=str(len(result["url"])) + " chars",
            fg=CLR_SUSPICIOUS if len(result["url"]) > 75 else FG_PRIMARY
        )
        self._detail_rows["tld"].configure(
            text=("." + ext.suffix) if ext.suffix else "—",
            fg=CLR_SUSPICIOUS if features.get("suspicious_tld") else FG_PRIMARY
        )

        # Rebuild breakdown list
        for widget in self.breakdown_inner.winfo_children():
            widget.destroy()

        all_items = [(r, p, False) for r, p in breakdown] + \
                    [(r, -p, True) for r, p in safe_sig]

        if not all_items:
            tk.Label(self.breakdown_inner,
                     text="No significant risk factors found.",
                     font=self.f_normal, fg=CLR_SAFE,
                     bg=BG_CARD, pady=12).pack(padx=16)
        else:
            for reason, points, is_safe in all_items:
                self._add_breakdown_row(reason, points, is_safe)

        self.breakdown_count.configure(
            text=f"{len(breakdown)} risk factor{'s' if len(breakdown) != 1 else ''}"
        )

        # Add to history
        self._add_history_entry(result["url"], risk, score, color, emoji)

        self.status_var.set(
            f"{emoji}  {risk}  ·  Score: {score}/100  ·  "
            f"{len(breakdown)} risk signal(s) detected  ·  {result['url'][:60]}"
        )

    def _add_breakdown_row(self, reason: str, points: int, is_safe: bool):
        color = CLR_SAFE if is_safe else (
            CLR_DANGEROUS if points >= 20 else CLR_SUSPICIOUS
        )
        # Alternating stripe
        row_count = len(self.breakdown_inner.winfo_children())
        row_bg = BG_CARD if row_count % 2 == 0 else BG_INPUT

        row = tk.Frame(self.breakdown_inner, bg=row_bg, pady=6)
        row.pack(fill="x")

        # Left colored indicator bar
        tk.Frame(row, bg=color, width=3).pack(side="left", fill="y", padx=(8, 8))

        # Reason text
        tk.Label(row, text=reason, font=self.f_normal,
                 fg=FG_PRIMARY, bg=row_bg, anchor="w",
                 wraplength=340).pack(side="left", fill="x", expand=True)

        # Points pill badge
        sign = "−" if is_safe else "+"
        badge = tk.Label(row, text=f" {sign}{abs(points)} ",
                         font=self.f_tag, fg=color, bg=BG_TAG,
                         padx=4, pady=2, relief="flat")
        badge.pack(side="right", padx=10)

    def _add_history_entry(self, url: str, risk: str, score: int,
                            color: str, emoji: str):
        self._history.insert(0, (url, risk, score, color, emoji))
        self._history = self._history[:20]  # keep last 20

        # Clear placeholder
        self._history_placeholder.pack_forget()

        # Rebuild (only top 10 shown)
        for widget in self.history_frame.winfo_children():
            widget.destroy()

        for url_, risk_, score_, color_, emoji_ in self._history[:10]:
            row = tk.Frame(self.history_frame, bg=BG_INPUT, pady=6, padx=10)
            row.pack(fill="x", pady=3)
            row.bind("<Button-1>", lambda e, u=url_: self._paste_example(u))
            row.configure(cursor="hand2")

            tk.Label(row, text=emoji_, font=self.f_normal,
                     bg=BG_INPUT).pack(side="left", padx=(0, 6))

            url_short = url_[:55] + "…" if len(url_) > 55 else url_
            tk.Label(row, text=url_short, font=self.f_mono,
                     fg=FG_PRIMARY, bg=BG_INPUT, anchor="w").pack(
                         side="left", fill="x", expand=True)

            tk.Label(row, text=f"{score_}", font=self.f_small,
                     fg=color_, bg=BG_INPUT).pack(side="right", padx=(4, 0))
            tk.Label(row, text=risk_, font=self.f_small,
                     fg=color_, bg=BG_INPUT).pack(side="right", padx=(0, 4))

    def _clear_history(self):
        self._history.clear()
        for widget in self.history_frame.winfo_children():
            widget.destroy()
        self._history_placeholder = tk.Label(
            self.history_frame, text="No scans yet.",
            font=self.f_normal, fg=FG_MUTED, bg=BG_CARD
        )
        self._history_placeholder.pack(pady=40)

    # ── Score ring + bar animation ────────────────────────────────────────────
    def _draw_score_ring(self, score: int, color: str):
        c = self.score_canvas
        c.delete("all")
        cx, cy, r = 78, 78, 58
        thickness = 13

        # Shadow ring
        c.create_arc(cx - r, cy - r, cx + r, cy + r,
                     start=0, extent=359.9,
                     outline=BG_INPUT, width=thickness, style="arc")
        # Filled arc
        extent = (score / 100) * 359.9
        if extent > 0:
            c.create_arc(cx - r, cy - r, cx + r, cy + r,
                         start=90, extent=-extent,
                         outline=color, width=thickness, style="arc")

    def _draw_bar(self, score: int, color: str):
        c = self.bar_canvas
        c.delete("all")
        w = c.winfo_width() or 200
        filled = int((score / 100) * w)
        c.create_rectangle(0, 0, w, 6, fill=BG_INPUT, outline="")
        if filled > 0:
            c.create_rectangle(0, 0, filled, 6, fill=color, outline="")

    def _animate_score(self, current: int, target: int, color: str):
        if self._anim_after_id:
            self.after_cancel(self._anim_after_id)

        def step(val):
            self._draw_score_ring(val, color)
            self._draw_bar(val, color)
            self.score_label.configure(text=str(val), fg=color)
            if val < target:
                next_val = min(val + 3, target)
                self._anim_after_id = self.after(16, lambda: step(next_val))

        step(current)

    # ── Flash entry on empty input ────────────────────────────────────────────
    def _flash_entry(self):
        original = self.url_entry.cget("highlightbackground")
        self.url_entry.configure(highlightbackground=CLR_DANGEROUS,
                                  highlightcolor=CLR_DANGEROUS)
        self.after(600, lambda: self.url_entry.configure(
            highlightbackground=BORDER, highlightcolor=FG_ACCENT))


if __name__ == "__main__":
    app = PhishingDetectorApp()
    app.mainloop()
