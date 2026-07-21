"""SentinelX desktop GUI.

Collects the target domain, an authorization confirmation, and a contact
email (no password, nothing beyond what a scan report already needs), then
runs the existing CLI pipeline (main.py) as a subprocess and streams its
output live. This is a thin front-end only — all scan/report logic still
lives in core/ and reporting/.
"""

from __future__ import annotations

import os
import queue
import re
import subprocess
import sys
import threading
from pathlib import Path
from tkinter import BooleanVar, StringVar, Tk, messagebox, ttk
from tkinter.scrolledtext import ScrolledText

LEGAL_SUMMARY = (
    "SentinelX performs active checks against the target (HTTP fetches, TCP port\n"
    "probes), not only passive lookups. Only scan a domain you own or hold explicit\n"
    "written authorization to assess. See LEGAL.md for the full terms."
)

SCOPES = ["quick", "standard", "deep"]
FORMATS = ["pdf", "html", "json", "all"]

_SLUG_PATTERN = re.compile(r"[^A-Za-z0-9.-]+")


def _safe_slug(domain: str) -> str:
    slug = _SLUG_PATTERN.sub("_", domain.strip().lower()).strip("._") or "scan"
    return slug[:80]


class SentinelXGui:
    def __init__(self, root: Tk) -> None:
        self.root = root
        root.title("SentinelX")
        root.geometry("660x600")
        root.minsize(580, 520)

        self.domain = StringVar()
        self.analyst_name = StringVar(value="SentinelX Automated Engine")
        self.analyst_email = StringVar()
        self.scope = StringVar(value="standard")
        self.output_format = StringVar(value="all")
        self.use_ai = BooleanVar(value=False)
        self.compare_last = BooleanVar(value=False)
        self.authorized = BooleanVar(value=False)

        self._log_queue: "queue.Queue[str]" = queue.Queue()
        self._process: subprocess.Popen | None = None
        self._output_dir = Path.cwd()

        self._build_form()
        self._poll_log_queue()

    def _build_form(self) -> None:
        pad = {"padx": 12, "pady": 6}
        frm = ttk.Frame(self.root)
        frm.pack(fill="both", expand=True)

        ttk.Label(frm, text="SentinelX — External Exposure Scan", font=("Georgia", 15, "bold")).grid(
            row=0, column=0, columnspan=2, sticky="w", padx=12, pady=(14, 2)
        )
        ttk.Label(frm, text="Authorized external recon and client-ready reporting for one domain at a time.").grid(
            row=1, column=0, columnspan=2, sticky="w", padx=12, pady=(0, 12)
        )

        row = 2
        ttk.Label(frm, text="Target domain").grid(row=row, column=0, sticky="w", **pad)
        ttk.Entry(frm, textvariable=self.domain, width=38).grid(row=row, column=1, sticky="ew", **pad)

        row += 1
        ttk.Label(frm, text="Your email (report contact line)").grid(row=row, column=0, sticky="w", **pad)
        ttk.Entry(frm, textvariable=self.analyst_email, width=38).grid(row=row, column=1, sticky="ew", **pad)

        row += 1
        ttk.Label(frm, text="Analyst / your name").grid(row=row, column=0, sticky="w", **pad)
        ttk.Entry(frm, textvariable=self.analyst_name, width=38).grid(row=row, column=1, sticky="ew", **pad)

        row += 1
        ttk.Label(frm, text="Scan depth").grid(row=row, column=0, sticky="w", **pad)
        ttk.Combobox(frm, textvariable=self.scope, values=SCOPES, state="readonly", width=35).grid(
            row=row, column=1, sticky="ew", **pad
        )

        row += 1
        ttk.Label(frm, text="Output format").grid(row=row, column=0, sticky="w", **pad)
        ttk.Combobox(frm, textvariable=self.output_format, values=FORMATS, state="readonly", width=35).grid(
            row=row, column=1, sticky="ew", **pad
        )

        row += 1
        ttk.Checkbutton(
            frm,
            text="Compare against last saved baseline  (--compare last)",
            variable=self.compare_last,
        ).grid(row=row, column=0, columnspan=2, sticky="w", padx=12)

        row += 1
        ttk.Checkbutton(
            frm,
            text="Use AI-assisted narrative summary  (requires OPENAI_API_KEY in environment)",
            variable=self.use_ai,
        ).grid(row=row, column=0, columnspan=2, sticky="w", padx=12)

        row += 1
        legal_box = ttk.LabelFrame(frm, text="Authorization required")
        legal_box.grid(row=row, column=0, columnspan=2, sticky="ew", padx=12, pady=(10, 4))
        ttk.Label(legal_box, text=LEGAL_SUMMARY, justify="left").pack(anchor="w", padx=10, pady=(8, 4))
        ttk.Checkbutton(
            legal_box,
            text="I own this domain, or I hold explicit written authorization to assess it.",
            variable=self.authorized,
            command=self._sync_run_state,
        ).pack(anchor="w", padx=10, pady=(0, 8))

        row += 1
        self.run_button = ttk.Button(frm, text="Run Scan", command=self._on_run, state="disabled")
        self.run_button.grid(row=row, column=0, sticky="w", padx=12, pady=(6, 6))
        self.open_output_button = ttk.Button(
            frm, text="Open Output Folder", command=self._open_output, state="disabled"
        )
        self.open_output_button.grid(row=row, column=1, sticky="e", padx=12, pady=(6, 6))

        row += 1
        self.log_box = ScrolledText(
            frm, height=14, font=("Courier New", 9), state="disabled", bg="#12161a", fg="#dce8dc"
        )
        self.log_box.grid(row=row, column=0, columnspan=2, sticky="nsew", padx=12, pady=(4, 12))

        frm.columnconfigure(1, weight=1)
        frm.rowconfigure(row, weight=1)

        self.domain.trace_add("write", lambda *_: self._sync_run_state())

    def _sync_run_state(self) -> None:
        ready = bool(self.domain.get().strip()) and self.authorized.get() and self._process is None
        self.run_button.configure(state="normal" if ready else "disabled")

    def _append_log(self, text: str) -> None:
        self.log_box.configure(state="normal")
        self.log_box.insert("end", text)
        self.log_box.see("end")
        self.log_box.configure(state="disabled")

    def _poll_log_queue(self) -> None:
        try:
            while True:
                line = self._log_queue.get_nowait()
                self._append_log(line)
        except queue.Empty:
            pass
        self.root.after(150, self._poll_log_queue)

    def _on_run(self) -> None:
        domain = self.domain.get().strip()
        if not domain:
            messagebox.showerror("SentinelX", "Enter a target domain first.")
            return
        if not self.authorized.get():
            messagebox.showerror("SentinelX", "Confirm authorization before running a scan.")
            return

        email = self.analyst_email.get().strip()
        if email and "@" not in email:
            if not messagebox.askyesno("SentinelX", f'"{email}" does not look like an email address. Continue anyway?'):
                return

        self.run_button.configure(state="disabled")
        self.open_output_button.configure(state="disabled")
        self._append_log(f"\n{'=' * 60}\nStarting scan of {domain}\n{'=' * 60}\n")

        script_dir = Path(__file__).resolve().parent
        self._output_dir = script_dir / "gui_output" / _safe_slug(domain)
        self._output_dir.mkdir(parents=True, exist_ok=True)

        cmd = [
            sys.executable,
            str(script_dir / "main.py"),
            "--domain", domain,
            "--scope", self.scope.get(),
            "--format", self.output_format.get(),
            "--analyst", self.analyst_name.get().strip() or "SentinelX Automated Engine",
            "--output-dir", str(self._output_dir),
            "--i-have-authorization",
        ]
        if email:
            cmd += ["--analyst-email", email]
        if self.compare_last.get():
            cmd += ["--compare", "last"]
        if self.use_ai.get():
            cmd += ["--ai"]

        thread = threading.Thread(target=self._run_process, args=(cmd,), daemon=True)
        thread.start()

    def _run_process(self, cmd: list[str]) -> None:
        return_code = 1
        try:
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            assert self._process.stdout is not None
            for line in self._process.stdout:
                self._log_queue.put(line)
            return_code = self._process.wait()
        except Exception as exc:  # noqa: BLE001
            self._log_queue.put(f"\nGUI failed to launch scan: {exc}\n")
        finally:
            self._process = None

        if return_code == 0:
            self._log_queue.put(f"\nDone. Output written to {self._output_dir}\n")
        else:
            self._log_queue.put(f"\nScan exited with code {return_code}. See log above.\n")

        self.root.after(0, self._on_process_done)

    def _on_process_done(self) -> None:
        self.open_output_button.configure(state="normal")
        self._sync_run_state()

    def _open_output(self) -> None:
        if not self._output_dir.exists():
            return
        if sys.platform == "win32":
            os.startfile(str(self._output_dir))
        elif sys.platform == "darwin":
            subprocess.Popen(["open", str(self._output_dir)])
        else:
            subprocess.Popen(["xdg-open", str(self._output_dir)])


def main() -> None:
    root = Tk()
    SentinelXGui(root)
    root.mainloop()


if __name__ == "__main__":
    main()
