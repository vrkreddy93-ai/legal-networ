"""Native desktop interface for Aegis Guard."""

from __future__ import annotations

import queue
import threading
import tkinter as tk
from tkinter import ttk
from typing import Any

from .cli import DEFAULT_PORTS
from .web import run_dashboard_scan


class AegisDesktopApp(ttk.Frame):
    """Focused local interface for one authorized posture assessment."""

    BG = "#f3f6fb"
    NAVY = "#14213d"
    MUTED = "#64748b"
    BLUE = "#2563eb"
    GREEN = "#15803d"

    def __init__(self, root: tk.Tk) -> None:
        super().__init__(root, padding=24)
        self.root = root
        self.result_queue: queue.Queue[dict[str, Any]] = queue.Queue()
        self.target = tk.StringVar()
        self.authorized = tk.BooleanVar(value=False)
        self.reference = tk.StringVar()
        self.ports = tk.StringVar(value=DEFAULT_PORTS)
        self.timeout = tk.StringVar(value="1.5")
        self.output = tk.StringVar(value="reports")
        self.output_format = tk.StringVar(value="both")
        self.status = tk.StringVar(value="Ready · preview checks scope without sending network traffic")
        self._build()

    def _build(self) -> None:
        self.root.title("Aegis Guard · Security Posture")
        self.root.minsize(760, 680)
        self.root.configure(bg=self.BG)
        self.configure(style="App.TFrame")
        self.grid(sticky="nsew")
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)
        self.rowconfigure(3, weight=1)

        header = ttk.Frame(self, style="App.TFrame")
        header.grid(row=0, column=0, sticky="ew", pady=(0, 18))
        ttk.Label(header, text="AEGIS  /  GUARD", style="Brand.TLabel").pack(anchor="w")
        ttk.Label(header, text="Website security posture", style="Title.TLabel").pack(anchor="w", pady=(7, 2))
        ttk.Label(header, text="A focused, low-impact assessment for a single authorized host.", style="Muted.TLabel").pack(anchor="w")

        form = ttk.LabelFrame(self, text="  Assessment scope  ", style="Card.TLabelframe", padding=18)
        form.grid(row=1, column=0, sticky="ew")
        form.columnconfigure(1, weight=1)
        self._entry(form, 0, "Website or IP address", self.target)
        ttk.Checkbutton(
            form,
            text="I own this host or have written permission to assess it.",
            variable=self.authorized,
            style="Consent.TCheckbutton",
        ).grid(row=1, column=0, columnspan=2, sticky="w", pady=(12, 6))

        options = ttk.Frame(form, style="Card.TFrame")
        options.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(6, 0))
        for col in (1, 3):
            options.columnconfigure(col, weight=1)
        self._entry(options, 0, "Authorization reference", self.reference)
        self._entry(options, 1, "Ports", self.ports)
        self._entry(options, 2, "Timeout (seconds)", self.timeout)
        self._entry(options, 3, "Report folder", self.output)
        ttk.Label(options, text="Report format", style="Field.TLabel").grid(row=4, column=0, sticky="w", pady=(10, 4))
        ttk.Combobox(options, state="readonly", textvariable=self.output_format, values=("both", "json", "markdown"), width=16).grid(row=4, column=1, sticky="ew", padx=(0, 18), pady=(10, 4))

        actions = ttk.Frame(self, style="App.TFrame")
        actions.grid(row=2, column=0, sticky="ew", pady=(14, 12))
        self.preview_button = ttk.Button(actions, text="Preview checks", style="Secondary.TButton", command=lambda: self._start(dry_run=True))
        self.preview_button.pack(side="left")
        self.scan_button = ttk.Button(actions, text="Run safe scan", style="Primary.TButton", command=lambda: self._start(dry_run=False))
        self.scan_button.pack(side="left", padx=(10, 0))
        ttk.Label(actions, textvariable=self.status, style="Muted.TLabel", wraplength=430).pack(side="left", padx=(18, 0))

        results = ttk.LabelFrame(self, text="  Results  ", style="Card.TLabelframe", padding=12)
        results.grid(row=3, column=0, sticky="nsew")
        results.columnconfigure(0, weight=1)
        results.rowconfigure(0, weight=1)
        self.transcript = tk.Text(
            results,
            height=14,
            wrap="word",
            state="disabled",
            font=("Cascadia Mono", 10),
            bg="#fbfdff",
            fg=self.NAVY,
            insertbackground=self.NAVY,
            relief="flat",
            padx=14,
            pady=12,
            highlightthickness=1,
            highlightbackground="#dce4ef",
        )
        self.transcript.grid(row=0, column=0, sticky="nsew")
        scrollbar = ttk.Scrollbar(results, orient="vertical", command=self.transcript.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.transcript.configure(yscrollcommand=scrollbar.set)

        ttk.Label(
            self,
            text="SAFE BY DESIGN   ·   One host only   ·   No ranges, credentials, payloads, logins, or load generation",
            style="Foot.TLabel",
            wraplength=740,
        ).grid(row=4, column=0, sticky="w", pady=(14, 0))

    @staticmethod
    def _entry(parent: ttk.Frame, row: int, label: str, variable: tk.StringVar) -> None:
        ttk.Label(parent, text=label, style="Field.TLabel").grid(row=row, column=0, sticky="w", padx=(0, 14), pady=(8, 4))
        ttk.Entry(parent, textvariable=variable).grid(row=row, column=1, sticky="ew", pady=(8, 4))

    def _payload(self) -> dict[str, Any]:
        return {
            "target": self.target.get(),
            "authorized": self.authorized.get(),
            "authorization_reference": self.reference.get(),
            "ports": self.ports.get(),
            "timeout": self.timeout.get(),
            "output": self.output.get(),
            "format": self.output_format.get(),
        }

    def _start(self, *, dry_run: bool) -> None:
        self.preview_button.configure(state="disabled")
        self.scan_button.configure(state="disabled")
        self.status.set("Preparing preview…" if dry_run else "Running bounded posture checks…")
        threading.Thread(target=self._run, args=(self._payload(), dry_run), daemon=True).start()
        self.after(100, self._poll_result)

    def _run(self, payload: dict[str, Any], dry_run: bool) -> None:
        try:
            self.result_queue.put(run_dashboard_scan(payload, dry_run=dry_run))
        except Exception as exc:
            self.result_queue.put({"ok": False, "transcript": f"Could not process the request: {exc}"})

    def _poll_result(self) -> None:
        try:
            result = self.result_queue.get_nowait()
        except queue.Empty:
            self.after(100, self._poll_result)
            return
        self.preview_button.configure(state="normal")
        self.scan_button.configure(state="normal")
        self.status.set("Complete · review the results below" if result.get("ok") else "Not completed · review the message below")
        self.transcript.configure(state="normal")
        self.transcript.delete("1.0", tk.END)
        self.transcript.insert("1.0", result.get("transcript", "No output returned."))
        self.transcript.configure(state="disabled")


def run_desktop() -> None:
    root = tk.Tk()
    style = ttk.Style(root)
    try:
        style.theme_use("vista")
    except tk.TclError:
        pass
    style.configure("App.TFrame", background=AegisDesktopApp.BG)
    style.configure("Card.TFrame", background="#ffffff")
    style.configure("Brand.TLabel", background=AegisDesktopApp.BG, foreground=AegisDesktopApp.BLUE, font=("Segoe UI", 9, "bold"))
    style.configure("Title.TLabel", background=AegisDesktopApp.BG, foreground=AegisDesktopApp.NAVY, font=("Segoe UI", 22, "bold"))
    style.configure("Muted.TLabel", background=AegisDesktopApp.BG, foreground=AegisDesktopApp.MUTED, font=("Segoe UI", 10))
    style.configure("Field.TLabel", background="#ffffff", foreground=AegisDesktopApp.NAVY, font=("Segoe UI", 9, "bold"))
    style.configure("Foot.TLabel", background=AegisDesktopApp.BG, foreground=AegisDesktopApp.MUTED, font=("Segoe UI", 8))
    style.configure("Card.TLabelframe", background="#ffffff", bordercolor="#dce4ef", relief="solid")
    style.configure("Card.TLabelframe.Label", background="#ffffff", foreground=AegisDesktopApp.NAVY, font=("Segoe UI", 10, "bold"))
    style.configure("Consent.TCheckbutton", background="#ffffff", foreground=AegisDesktopApp.GREEN, font=("Segoe UI", 9, "bold"))
    style.configure("Primary.TButton", font=("Segoe UI", 10, "bold"), padding=(16, 9))
    style.configure("Secondary.TButton", font=("Segoe UI", 10), padding=(16, 9))
    AegisDesktopApp(root)
    root.mainloop()


