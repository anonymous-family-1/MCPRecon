#!/usr/bin/env python3
"""MCPRecon GUI for newline-delimited JSON (JSONL).

Usage:
    python mcprecon_gui.py [path_to_jsonl]

Defaults to reading `dbl_cursor_snapshot15.jsonl` in the current directory.
The interface shows all objects initially. Typing in the search box filters to
objects whose pretty-printed JSON contains the search term (case-insensitive).
Click an item in the list to view the full JSON with indentation.
"""

from __future__ import annotations

import json
import sys
import re
import subprocess
import threading
import queue
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import tkinter.font as tkfont


DEFAULT_FILE = Path("dbl_cursor_snapshot15.jsonl")
MCPSNIFFER = Path(__file__).with_name("mcprecon.py")


def load_jsonl(path: Path):
    """Load newline-delimited JSON objects from `path`.

    Returns a list of (index, original_text, parsed_obj, pretty_text).
    """

    records = []
    try:
        with path.open("r", encoding="utf-8") as fh:
            for idx, line in enumerate(fh):
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    obj = {"_raw": line, "_error": "Failed to decode JSON"}
                pretty = json.dumps(obj, indent=2, ensure_ascii=False)
                records.append((idx, line, obj, pretty))
    except FileNotFoundError:
        messagebox.showerror("File not found", f"Could not open: {path}")
        sys.exit(1)
    return records


class JsonlViewer(tk.Tk):
    def __init__(self, initial_path: Path | None = None):
        super().__init__()
        self.title("MCPRecon")
        self.geometry("1100x820")
        self.records = []
        self.filtered = []
        self.run_thread: threading.Thread | None = None
        self.log_queue: queue.Queue[str] = queue.Queue()
        self.running = False
        # Sublime-like monospace stack: Menlo → Consolas → DejaVu Sans Mono
        family = self._choose_font_family(["Menlo", "Consolas", "DejaVu Sans Mono", "monospace"])
        self.text_font = tkfont.Font(family=family, size=12, weight="normal")

        self._build_controls()
        self._build_ui()
        if initial_path and initial_path.exists():
            self.load_jsonl_path(initial_path)

    def _build_controls(self):
        controls = ttk.LabelFrame(self, text="Input & Extraction", padding=8)
        controls.pack(fill=tk.X, padx=8, pady=(8, 4))

        self.mem_path_var = tk.StringVar()
        self.out_path_var = tk.StringVar()
        self.keywords_var = tk.StringVar(value="jsonrpc,tools/list,tools/call")
        self.window_var = tk.IntVar(value=16384)
        self.emit_raw_var = tk.BooleanVar(value=False)
        self.tools_only_var = tk.BooleanVar(value=False)
        self.mcp_only_var = tk.BooleanVar(value=False)

        ttk.Label(controls, text="Memory image:").grid(row=0, column=0, sticky=tk.W)
        mem_entry = ttk.Entry(controls, textvariable=self.mem_path_var, width=70)
        mem_entry.grid(row=0, column=1, sticky=tk.EW, padx=(6, 6))
        ttk.Button(controls, text="Browse", command=self._choose_mem).grid(row=0, column=2, padx=(0, 6))

        ttk.Label(controls, text="Output JSONL:").grid(row=1, column=0, sticky=tk.W)
        out_entry = ttk.Entry(controls, textvariable=self.out_path_var, width=70)
        out_entry.grid(row=1, column=1, sticky=tk.EW, padx=(6, 6))
        ttk.Button(controls, text="Browse", command=self._choose_out).grid(row=1, column=2, padx=(0, 6))

        ttk.Label(controls, text="Keywords:").grid(row=2, column=0, sticky=tk.W)
        ttk.Entry(controls, textvariable=self.keywords_var).grid(row=2, column=1, sticky=tk.EW, padx=(6, 6))
        ttk.Label(controls, text="Window bytes:").grid(row=2, column=2, sticky=tk.W)
        ttk.Spinbox(controls, from_=1024, to=1_000_000, increment=1024, textvariable=self.window_var, width=10).grid(row=2, column=3, sticky=tk.W)

        opts = ttk.Frame(controls)
        opts.grid(row=3, column=0, columnspan=4, sticky=tk.W, pady=(6, 2))
        ttk.Checkbutton(opts, text="Emit raw", variable=self.emit_raw_var).pack(side=tk.LEFT)
        ttk.Checkbutton(opts, text="Tools only", variable=self.tools_only_var).pack(side=tk.LEFT, padx=(10, 0))
        ttk.Checkbutton(opts, text="MCP only", variable=self.mcp_only_var).pack(side=tk.LEFT, padx=(10, 0))

        btns = ttk.Frame(controls)
        btns.grid(row=4, column=0, columnspan=4, sticky=tk.W, pady=(6, 0))
        ttk.Button(btns, text="Run mcprecon", command=self._start_mcpsniffer).pack(side=tk.LEFT)
        ttk.Button(btns, text="Load JSONL", command=self._choose_jsonl).pack(side=tk.LEFT, padx=(8, 0))

        controls.columnconfigure(1, weight=1)

        log_frame = ttk.LabelFrame(self, text="Extraction log", padding=4)
        log_frame.pack(fill=tk.BOTH, padx=8, pady=(0, 8))
        self.log_text = tk.Text(log_frame, height=6, wrap=tk.WORD)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        log_scroll = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_scroll.set)
        log_scroll.pack(side=tk.RIGHT, fill=tk.Y)

    def _choose_font_family(self, preferred):
        """Return the first available font family from preferred list."""
        available = set(tkfont.families())
        for name in preferred:
            if name in available:
                return name
        return "monospace"

    def _build_ui(self):
        # Top bar with search entry
        top = ttk.Frame(self, padding=8)
        top.pack(fill=tk.X)

        ttk.Label(top, text="Search:").pack(side=tk.LEFT)
        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(top, textvariable=self.search_var)
        self.search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(6, 6))
        self.search_entry.bind("<KeyRelease>", self._on_search)

        clear_btn = ttk.Button(top, text="Clear", command=self._clear_search)
        clear_btn.pack(side=tk.LEFT)

        # Toggle line wrapping for long JSON
        self.wrap_var = tk.BooleanVar(value=False)
        wrap_btn = ttk.Checkbutton(top, text="Wrap long lines", variable=self.wrap_var, command=self._toggle_wrap)
        wrap_btn.pack(side=tk.LEFT, padx=(8, 0))

        # Font size controls
        ttk.Label(top, text="Font:").pack(side=tk.LEFT, padx=(10, 2))
        ttk.Button(top, text="-", width=3, command=lambda: self._change_font(-1)).pack(side=tk.LEFT)
        ttk.Button(top, text="+", width=3, command=lambda: self._change_font(+1)).pack(side=tk.LEFT, padx=(2, 0))

        # Main area: list on the left, details on the right
        main = ttk.Panedwindow(self, orient=tk.HORIZONTAL)
        main.pack(fill=tk.BOTH, expand=True)

        left_frame = ttk.Frame(main, padding=4)
        right_frame = ttk.Frame(main, padding=4)
        main.add(left_frame, weight=1)
        main.add(right_frame, weight=2)

        # List of summaries
        self.listbox = tk.Listbox(left_frame, exportselection=False)
        self.listbox.pack(fill=tk.BOTH, expand=True)
        self.listbox.bind("<<ListboxSelect>>", self._on_select)

        y_scroll = ttk.Scrollbar(left_frame, orient=tk.VERTICAL, command=self.listbox.yview)
        self.listbox.configure(yscrollcommand=y_scroll.set)
        y_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        # Detail text
        self.text = tk.Text(right_frame, wrap=tk.NONE, font=self.text_font)
        self.text.pack(fill=tk.BOTH, expand=True)

        y_text_scroll = ttk.Scrollbar(right_frame, orient=tk.VERTICAL, command=self.text.yview)
        x_text_scroll = ttk.Scrollbar(right_frame, orient=tk.HORIZONTAL, command=self.text.xview)
        self.text.configure(yscrollcommand=y_text_scroll.set, xscrollcommand=x_text_scroll.set)
        y_text_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        x_text_scroll.pack(side=tk.BOTTOM, fill=tk.X)

        # Syntax highlighting colors
        self.text.tag_configure("string", foreground="#1c7ed6")
        self.text.tag_configure("number", foreground="#d6336c")
        self.text.tag_configure("bool", foreground="#f08c00")
        self.text.tag_configure("null", foreground="#f08c00")
        self.text.tag_configure("brace", foreground="#868e96")
        self.text.tag_configure("colon", foreground="#adb5bd")
        self.text.tag_configure("comma", foreground="#adb5bd")

        # Keyboard shortcut to focus search
        self.bind("<Control-f>", lambda _e: self._focus_search())

    def _toggle_wrap(self):
        """Enable/disable word wrapping for long JSON lines."""
        wrap_mode = tk.WORD if self.wrap_var.get() else tk.NONE
        self.text.configure(wrap=wrap_mode)

    def _change_font(self, delta: int):
        """Increase or decrease the JSON view font size."""
        new_size = max(8, min(32, self.text_font.cget("size") + delta))
        self.text_font.configure(size=new_size)

    def _apply_syntax_highlight(self, text_content: str):
        """Lightweight JSON syntax highlighting using text tags."""
        for tag in ("string", "number", "bool", "null", "brace", "colon", "comma"):
            self.text.tag_remove(tag, "1.0", tk.END)

        # Helper to map absolute offset to Tk index
        def offset_to_index(offset: int) -> str:
            line = text_content.count("\n", 0, offset) + 1
            last_newline = text_content.rfind("\n", 0, offset)
            col = offset if last_newline == -1 else offset - last_newline - 1
            return f"{line}.{col}"

        string_spans = []
        for m in re.finditer(r'"(\\.|[^"\\])*"', text_content):
            start, end = m.start(), m.end()
            string_spans.append((start, end))
            self.text.tag_add("string", offset_to_index(start), offset_to_index(end))

        def in_string(pos: int) -> bool:
            return any(s <= pos < e for s, e in string_spans)

        patterns = [
            ("number", re.compile(r"\b-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?\b")),
            ("bool", re.compile(r"\btrue\b|\bfalse\b")),
            ("null", re.compile(r"\bnull\b")),
            ("brace", re.compile(r"[{}\[\]]")),
            ("colon", re.compile(r":")),
            ("comma", re.compile(r",")),
        ]

        for tag, regex in patterns:
            for m in regex.finditer(text_content):
                start, end = m.start(), m.end()
                if in_string(start):
                    continue
                self.text.tag_add(tag, offset_to_index(start), offset_to_index(end))

    def _summary(self, record):
        idx, line, obj, _pretty = record
        if isinstance(obj, dict):
            keys = list(obj.keys())[:3]
            key_str = ", ".join(keys)
        else:
            key_str = type(obj).__name__
        return f"[{idx}] {key_str}"

    def _populate_list(self):
        self.listbox.delete(0, tk.END)
        for rec in self.filtered:
            self.listbox.insert(tk.END, self._summary(rec))
        if self.filtered:
            self.listbox.select_set(0)
            self._show_record(self.filtered[0])
        else:
            self.text.delete("1.0", tk.END)
            self.text.insert(tk.END, "No results")

    def _show_record(self, record):
        _idx, line, _obj, pretty = record
        self.text.delete("1.0", tk.END)
        self.text.insert(tk.END, pretty)
        self._apply_syntax_highlight(pretty)

    def _on_select(self, _event):
        sel = self.listbox.curselection()
        if not sel:
            return
        record = self.filtered[sel[0]]
        self._show_record(record)

    def _on_search(self, _event=None):
        term = self.search_var.get().strip().lower()
        if not term:
            self.filtered = self.records
        else:
            self.filtered = [rec for rec in self.records if term in rec[3].lower()]
        self._populate_list()

    def _clear_search(self):
        self.search_var.set("")
        self._on_search()

    def _focus_search(self):
        self.focus_set()
        self.search_var.set("")
        if hasattr(self, "search_entry"):
            self.search_entry.focus_set()

    # -------- File selection & loading --------
    def _choose_mem(self):
        path = filedialog.askopenfilename(
            title="Select memory image",
            filetypes=[
                ("Memory images", "*.vmem *.raw *.bin *.img *.dmp *.mem"),
                ("All files", "*.*"),
            ],
        )
        if path:
            self.mem_path_var.set(path)
            if not self.out_path_var.get():
                self.out_path_var.set(str(Path(path).with_suffix(".jsonl")))

    def _choose_out(self):
        path = filedialog.asksaveasfilename(
            title="Save JSONL output",
            defaultextension=".jsonl",
            filetypes=[("JSONL", "*.jsonl"), ("All files", "*.*")],
        )
        if path:
            self.out_path_var.set(path)

    def _choose_jsonl(self):
        path = filedialog.askopenfilename(
            title="Open JSONL",
            filetypes=[("JSONL", "*.jsonl *.jsonnl"), ("All files", "*.*")],
        )
        if path:
            self.load_jsonl_path(Path(path))

    def load_jsonl_path(self, path: Path):
        records = load_jsonl(path)
        self.records = records
        self.filtered = records
        self._populate_list()
        self._append_log(f"[+] Loaded {len(records)} records from {path}")

    # -------- Logging --------
    def _append_log(self, msg: str):
        self.log_text.insert(tk.END, msg + "\n")
        self.log_text.see(tk.END)

    def _poll_log(self):
        try:
            while True:
                msg = self.log_queue.get_nowait()
                self._append_log(msg)
        except queue.Empty:
            pass
        if self.running:
            self.after(150, self._poll_log)

    # -------- mcpsniffer integration --------
    def _start_mcpsniffer(self):
        if self.running:
            messagebox.showinfo("Busy", "mcpsniffer is already running.")
            return

        mem_path = Path(self.mem_path_var.get().strip()) if self.mem_path_var.get().strip() else None
        if not mem_path or not mem_path.exists():
            messagebox.showerror("Missing file", "Please choose a memory image to process.")
            return

        out_path = Path(self.out_path_var.get().strip()) if self.out_path_var.get().strip() else mem_path.with_suffix(".jsonl")
        self.out_path_var.set(str(out_path))

        kw = [k.strip() for k in self.keywords_var.get().split(",") if k.strip()]
        if not kw:
            kw = ["jsonrpc", "tools/list", "tools/call"]
        window = max(1024, int(self.window_var.get()))

        cmd = [sys.executable, str(MCPSNIFFER), str(mem_path), "--window", str(window), "--keywords", *kw]
        if self.emit_raw_var.get():
            cmd.append("--emit-raw")
        if self.tools_only_var.get():
            cmd.append("--tools-only")
        if self.mcp_only_var.get():
            cmd.append("--mcp-only")

        self._append_log(f"[+] Running: {' '.join(cmd)}")
        self.running = True
        self.after(150, self._poll_log)

        def worker():
            try:
                with open(out_path, "w", encoding="utf-8") as outf:
                    proc = subprocess.Popen(cmd, stdout=outf, stderr=subprocess.PIPE, text=True)
                    if proc.stderr:
                        for line in proc.stderr:
                            self.log_queue.put(line.rstrip())
                    ret = proc.wait()
                if ret == 0:
                    self.log_queue.put(f"[+] Done. Output -> {out_path}")
                    self.after(0, lambda: self.load_jsonl_path(out_path))
                else:
                    self.log_queue.put(f"[!] mcprecon exited with code {ret}")
            except FileNotFoundError:
                self.log_queue.put("[!] mcprecon.py not found beside GUI script.")
            except Exception as exc:  # pragma: no cover - defensive logging
                self.log_queue.put(f"[!] Error: {exc}")
            finally:
                self.after(0, self._mark_idle)

        self.run_thread = threading.Thread(target=worker, daemon=True)
        self.run_thread.start()

    def _mark_idle(self):
        self.running = False
        self.run_thread = None


def main():
    initial = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_FILE
    app = JsonlViewer(initial if initial.exists() else None)
    app.mainloop()


if __name__ == "__main__":
    main()
