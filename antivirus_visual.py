import hashlib
import os
import queue
import shutil
import subprocess
import sys
import threading
import time
from collections import defaultdict
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Dict, List, Optional, Tuple

SUSPICIOUS_EXTENSIONS = {
    ".exe",
    ".bat",
    ".cmd",
    ".com",
    ".scr",
    ".pif",
    ".msi",
    ".cpl",
    ".js",
    ".vbs",
    ".ps1",
    ".hta",
    ".docm",
    ".xlsm",
    ".pptm",
    ".lnk",
}

MAX_ROWS_PER_TABLE = 1200


def file_hash(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as file_handle:
        for chunk in iter(lambda: file_handle.read(4096), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def human_size(size: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    value = float(size)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} {unit}"
        value /= 1024
    return f"{size} B"


def scan_folder(path: Path, event_queue: queue.Queue) -> None:
    started = time.perf_counter()
    safe_files = []
    warning_files = []
    dangerous_files = []
    hash_map = defaultdict(list)
    file_sizes = []
    errors = []

    try:
        files = [entry for entry in path.rglob("*") if entry.is_file()]
    except (PermissionError, OSError) as error:
        event_queue.put(("error", f"Cannot access this folder: {error}"))
        return

    total = len(files)
    event_queue.put(("start", total))

    if total == 0:
        event_queue.put(
            (
                "done",
                {
                    "total": 0,
                    "safe": safe_files,
                    "warning": warning_files,
                    "dangerous": dangerous_files,
                    "duplicates": {},
                    "sizes": file_sizes,
                    "errors": errors,
                    "elapsed": time.perf_counter() - started,
                },
            )
        )
        return

    for index, file_path in enumerate(files, start=1):
        try:
            suffixes = file_path.suffixes
            if len(suffixes) > 1:
                dangerous_files.append(file_path)
            elif file_path.suffix.lower() in SUSPICIOUS_EXTENSIONS:
                warning_files.append(file_path)
            else:
                safe_files.append(file_path)

            file_sizes.append((file_path, file_path.stat().st_size))
            hash_map[file_hash(file_path)].append(file_path)
        except (PermissionError, OSError) as error:
            errors.append(f"{file_path}: {error}")

        if index == total or index % 10 == 0:
            event_queue.put(("progress", index, total, file_path.name))

    duplicates = {hash_key: group for hash_key, group in hash_map.items() if len(group) > 1}
    file_sizes.sort(key=lambda item: item[1], reverse=True)

    event_queue.put(
        (
            "done",
            {
                "total": total,
                "safe": safe_files,
                "warning": warning_files,
                "dangerous": dangerous_files,
                "duplicates": duplicates,
                "sizes": file_sizes,
                "errors": errors,
                "elapsed": time.perf_counter() - started,
            },
        )
    )


class AntivirusVisualApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.language_var = tk.StringVar(value="English")
        self.theme_var = tk.StringVar(value="Light")

        self.translations = {
            "English": {
                "title": "Antivirus Visual Scanner",
                "header_title": "Antivirus Visual Scanner",
                "header_subtitle": "Fast folder scan with clean threat, duplicate and size overview.",
                "label_folder": "Folder:",
                "btn_browse": "Browse",
                "btn_scan": "Start Scan",
                "btn_settings": "Settings",
                "status_initial": "Select a folder and start scanning.",
                "tab_threats": "Threats",
                "tab_duplicates": "Duplicates",
                "tab_sizes": "Largest Files",
                "summary_total": "Total files: {count}",
                "summary_safe": "Safe: {count}",
                "summary_warning": "Warning: {count}",
                "summary_danger": "Danger: {count}",
                "summary_duplicates": "Duplicate groups: {count}",
                "summary_errors": "Errors: {count}",
                "settings_title": "Settings",
                "settings_theme": "Theme",
                "settings_language": "Language",
                "settings_apply": "Apply",
                "settings_close": "Close",
            },
            "Українська": {
                "title": "Антивірусний сканер",
                "header_title": "Антивірусний сканер",
                "header_subtitle": "Швидке сканування папки з оглядом загроз, дублікатів та розміру файлів.",
                "label_folder": "Папка:",
                "btn_browse": "Обрати",
                "btn_scan": "Почати сканування",
                "btn_settings": "Налаштування",
                "status_initial": "Оберіть папку та запустіть сканування.",
                "tab_threats": "Загрози",
                "tab_duplicates": "Дублікаті",
                "tab_sizes": "Найбільші файли",
                "summary_total": "Всього файлів: {count}",
                "summary_safe": "Безпечні: {count}",
                "summary_warning": "Попередження: {count}",
                "summary_danger": "Небезпечні: {count}",
                "summary_duplicates": "Груп дублікатів: {count}",
                "summary_errors": "Помилки: {count}",
                "settings_title": "Налаштування",
                "settings_theme": "Тема",
                "settings_language": "Мова",
                "settings_apply": "Застосувати",
                "settings_close": "Закрити",
            },
        }

        current_texts = self.translations[self.language_var.get()]
        self.root.title(current_texts["title"])
        self.root.geometry("1120x760")
        self.root.minsize(960, 620)

        self.queue: Optional[queue.Queue] = None
        self.scan_thread: Optional[threading.Thread] = None

        self.folder_var = tk.StringVar()
        self.status_var = tk.StringVar(value=current_texts["status_initial"])
        self.progress_var = tk.DoubleVar(value=0)

        self.total_label_var = tk.StringVar()
        self.safe_label_var = tk.StringVar()
        self.warning_label_var = tk.StringVar()
        self.danger_label_var = tk.StringVar()
        self.duplicate_label_var = tk.StringVar()
        self.error_label_var = tk.StringVar()

        self.counts = {
            "total": 0,
            "safe": 0,
            "warning": 0,
            "danger": 0,
            "duplicates": 0,
            "errors": 0,
        }
        self.active_threat_item: Optional[str] = None

        self._setup_style()
        self._build_layout()

    def _setup_style(self) -> None:
        theme = self.theme_var.get() if hasattr(self, "theme_var") else "Light"
        if theme == "Dark":
            palette = {
                "bg": "#0a0d14",
                "card": "#111522",
                "surface": "#0f1420",
                "border": "#273246",
                "accent": "#23304a",
                "text": "#e6edf7",
                "muted": "#9aa4b2",
                "safe": "#22c55e",
                "warning": "#f59e0b",
                "danger": "#fb7185",
            }
        else:
            palette = {
                "bg": "#f4f7fb",
                "card": "#ffffff",
                "accent": "#0f62fe",
                "text": "#0f172a",
                "muted": "#51607a",
                "safe": "#1b8f3c",
                "warning": "#d17900",
                "danger": "#be123c",
            }
        self.palette = palette

        self.root.configure(bg=palette["bg"])
        style = ttk.Style(self.root)
        style.theme_use("clam")

        style.configure("TFrame", background=palette["bg"])
        style.configure(
            "Card.TFrame",
            background=palette["card"],
            relief="solid" if theme == "Dark" else "flat",
            borderwidth=1 if theme == "Dark" else 0,
        )
        style.configure(
            "Title.TLabel",
            font=("Segoe UI", 24, "bold"),
            foreground=palette["text"],
            background=palette["bg"],
        )
        style.configure(
            "Subtitle.TLabel",
            font=("Segoe UI", 11),
            foreground=palette["muted"],
            background=palette["bg"],
        )
        style.configure(
            "Header.TLabel",
            font=("Segoe UI", 10, "bold"),
            foreground=palette["muted"],
            background=palette["card"],
        )
        style.configure(
            "Value.TLabel",
            font=("Segoe UI", 14, "bold"),
            foreground=palette["text"],
            background=palette["card"],
        )

        style.configure(
            "Primary.TButton",
            font=("Segoe UI", 10, "bold"),
            padding=(12, 8),
            foreground="white",
            background=palette["accent"],
            borderwidth=0,
        )
        style.map(
            "Primary.TButton",
            background=[
                ("active", "#2b3854" if theme == "Dark" else "#0b4dc4"),
                ("disabled", "#1a2233" if theme == "Dark" else "#a6bff6"),
            ],
            foreground=[("disabled", "#9aa4b2" if theme == "Dark" else "#f2f5ff")],
        )

        if theme == "Dark":
            style.configure(
                "TEntry",
                fieldbackground=palette["surface"],
                foreground=palette["text"],
                bordercolor=palette["border"],
                relief="flat",
                padding=8,
                insertcolor=palette["text"],
            )
            style.configure(
                "TNotebook",
                background=palette["bg"],
                borderwidth=0,
                tabmargins=(0, 0, 0, 0),
            )
            style.configure(
                "TNotebook.Tab",
                font=("Segoe UI", 10, "bold"),
                padding=(12, 8),
                background=palette["surface"],
                foreground=palette["text"],
            )
            style.map(
                "TNotebook.Tab",
                background=[("selected", palette["card"]), ("active", "#141b2a")],
                foreground=[("selected", palette["text"]), ("active", palette["text"])],
            )

            style.configure(
                "Horizontal.TProgressbar",
                troughcolor=palette["surface"],
                background=palette["accent"],
                bordercolor=palette["surface"],
                lightcolor=palette["accent"],
                darkcolor=palette["accent"],
                thickness=15,
            )

            style.configure(
                "Treeview",
                background=palette["surface"],
                fieldbackground=palette["surface"],
                foreground=palette["text"],
                rowheight=25,
                font=("Segoe UI", 10),
                bordercolor=palette["border"],
            )
            style.configure(
                "Treeview.Heading",
                font=("Segoe UI", 10, "bold"),
                foreground=palette["text"],
                background=palette["card"],
            )
            style.map(
                "Treeview",
                background=[("selected", "#1f2a3a")],
                foreground=[("selected", palette["text"])],
            )
            style.configure(
                "TCombobox",
                fieldbackground=palette["surface"],
                foreground=palette["text"],
                background=palette["surface"],
                bordercolor=palette["border"],
                arrowsize=14,
                padding=6,
            )
            style.map(
                "TCombobox",
                fieldbackground=[("readonly", palette["surface"])],
                foreground=[("readonly", palette["text"])],
            )
            style.configure(
                "TScrollbar",
                background=palette["surface"],
                troughcolor=palette["bg"],
                bordercolor=palette["bg"],
                arrowcolor=palette["muted"],
            )
        else:
            style.configure(
                "TEntry",
                fieldbackground="white",
                bordercolor="#d2dae8",
                relief="flat",
                padding=8,
            )
            style.configure(
                "TNotebook",
                background=palette["bg"],
                borderwidth=0,
                tabmargins=(0, 0, 0, 0),
            )
            style.configure(
                "TNotebook.Tab",
                font=("Segoe UI", 10, "bold"),
                padding=(12, 8),
                background="#dce6fb",
                foreground=palette["text"],
            )
            style.map("TNotebook.Tab", background=[("selected", "#ffffff")])

            style.configure(
                "Horizontal.TProgressbar",
                troughcolor="#e0e8f7",
                background=palette["accent"],
                bordercolor="#e0e8f7",
                lightcolor=palette["accent"],
                darkcolor=palette["accent"],
                thickness=15,
            )

            style.configure(
                "Treeview",
                background="white",
                fieldbackground="white",
                rowheight=25,
                font=("Segoe UI", 10),
                bordercolor="#dbe2ef",
            )
            style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"))

    def _build_layout(self) -> None:
        texts = self.translations[self.language_var.get()]

        main = ttk.Frame(self.root, padding=18)
        main.pack(fill="both", expand=True)
        self.main_frame = main

        header = ttk.Frame(main)
        header.pack(fill="x")
        self.header_title_label = ttk.Label(header, text=texts["header_title"], style="Title.TLabel")
        self.header_title_label.pack(anchor="w")
        self.header_subtitle_label = ttk.Label(
            header,
            text=texts["header_subtitle"],
            style="Subtitle.TLabel",
        )
        self.header_subtitle_label.pack(anchor="w", pady=(2, 12))

        controls = ttk.Frame(main, style="Card.TFrame", padding=14)
        controls.pack(fill="x")

        ttk.Label(controls, text=texts["label_folder"], style="Header.TLabel").grid(
            row=0, column=0, sticky="w"
        )
        self.folder_entry = ttk.Entry(controls, textvariable=self.folder_var)
        self.folder_entry.grid(row=1, column=0, sticky="ew", padx=(0, 8), pady=(4, 0))

        self.browse_btn = ttk.Button(controls, text=texts["btn_browse"], command=self.pick_folder)
        self.browse_btn.grid(row=1, column=1, sticky="ew", padx=(0, 8), pady=(4, 0))

        self.scan_btn = ttk.Button(
            controls,
            text=texts["btn_scan"],
            style="Primary.TButton",
            command=self.start_scan,
        )
        self.scan_btn.grid(row=1, column=2, sticky="ew", pady=(4, 0))

        self.settings_btn = ttk.Button(
            controls,
            text=texts["btn_settings"],
            command=self.open_settings,
        )
        self.settings_btn.grid(row=1, column=3, sticky="ew", padx=(8, 0), pady=(4, 0))

        controls.columnconfigure(0, weight=1)

        progress_card = ttk.Frame(main, style="Card.TFrame", padding=(14, 12))
        progress_card.pack(fill="x", pady=(12, 10))

        self.progress = ttk.Progressbar(
            progress_card,
            orient="horizontal",
            mode="determinate",
            variable=self.progress_var,
            maximum=100,
        )
        self.progress.pack(fill="x")
        ttk.Label(progress_card, textvariable=self.status_var, style="Subtitle.TLabel").pack(
            anchor="w", pady=(8, 0)
        )

        stat_row = ttk.Frame(main)
        stat_row.pack(fill="x", pady=(0, 12))

        cards = [
            self.total_label_var,
            self.safe_label_var,
            self.warning_label_var,
            self.danger_label_var,
            self.duplicate_label_var,
            self.error_label_var,
        ]
        for idx, variable in enumerate(cards):
            card = ttk.Frame(stat_row, style="Card.TFrame", padding=10)
            card.grid(row=0, column=idx, padx=(0 if idx == 0 else 8, 0), sticky="nsew")
            ttk.Label(card, textvariable=variable, style="Value.TLabel").pack(anchor="w")
            stat_row.columnconfigure(idx, weight=1)

        notebook_wrap = ttk.Frame(main, style="Card.TFrame", padding=10)
        notebook_wrap.pack(fill="both", expand=True)

        notebook = ttk.Notebook(notebook_wrap)
        notebook.pack(fill="both", expand=True)
        self.notebook = notebook

        threats_tab = ttk.Frame(notebook)
        self.threats_tab = threats_tab
        notebook.add(threats_tab, text=texts["tab_threats"])
        self.threats_tree = self._build_tree(
            threats_tab,
            columns=("status", "file", "notes"),
            headings=("Status", "File", "Notes"),
            widths=(110, 520, 280),
        )
        self.threats_tree.tag_configure("safe", foreground=self.palette["safe"])
        self.threats_tree.tag_configure("warning", foreground=self.palette["warning"])
        self.threats_tree.tag_configure("danger", foreground=self.palette["danger"])
        self.threats_tree.tag_configure("resolved", foreground="#64748b")
        self.threats_tree.bind("<Double-1>", self.on_threat_double_click)
        self.threats_tree.bind("<Button-3>", self.on_threat_context_menu)
        self.threats_tree.bind("<Button-2>", self.on_threat_context_menu)

        self.threat_menu = tk.Menu(self.root, tearoff=0)
        self.threat_menu.add_command(
            label="Quarantine file",
            command=lambda: self.apply_threat_action("quarantine"),
        )
        self.threat_menu.add_command(
            label="Delete file",
            command=lambda: self.apply_threat_action("delete"),
        )
        self.threat_menu.add_command(
            label="Open file location",
            command=lambda: self.apply_threat_action("open_location"),
        )
        self.threat_menu.add_command(
            label="Ignore warning",
            command=lambda: self.apply_threat_action("ignore"),
        )
        self._apply_menu_theme()

        dup_tab = ttk.Frame(notebook)
        self.duplicates_tab = dup_tab
        notebook.add(dup_tab, text=texts["tab_duplicates"])
        self.duplicates_tree = self._build_tree(
            dup_tab,
            columns=("hash", "count", "files"),
            headings=("Hash (SHA-256)", "Count", "Example Files"),
            widths=(220, 100, 620),
        )

        size_tab = ttk.Frame(notebook)
        self.size_tab = size_tab
        notebook.add(size_tab, text=texts["tab_sizes"])
        self.size_tree = self._build_tree(
            size_tab,
            columns=("file", "size"),
            headings=("File", "Size"),
            widths=(780, 140),
        )

    def _build_tree(
        self,
        parent: ttk.Frame,
        columns: Tuple[str, ...],
        headings: Tuple[str, ...],
        widths: Tuple[int, ...],
    ) -> ttk.Treeview:
        wrap = ttk.Frame(parent)
        wrap.pack(fill="both", expand=True)

        tree = ttk.Treeview(wrap, columns=columns, show="headings")
        for column, heading, width in zip(columns, headings, widths):
            tree.heading(column, text=heading)
            tree.column(column, width=width, anchor="w")

        scroll_y = ttk.Scrollbar(wrap, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scroll_y.set)

        tree.pack(side="left", fill="both", expand=True)
        scroll_y.pack(side="right", fill="y")
        return tree

    def pick_folder(self) -> None:
        selected = filedialog.askdirectory(title="Select folder for scan")
        if selected:
            self.folder_var.set(selected)

    def start_scan(self) -> None:
        folder = self.folder_var.get().strip()
        if not folder:
            messagebox.showwarning("Folder required", "Please select a folder before scanning.")
            return

        path = Path(folder)
        if not path.exists() or not path.is_dir():
            messagebox.showerror("Invalid folder", "Selected path is not a valid folder.")
            return

        if self.scan_thread and self.scan_thread.is_alive():
            messagebox.showinfo("Scan in progress", "Please wait for the current scan to finish.")
            return

        self.clear_tables()
        self._reset_counts()
        self.progress_var.set(0)
        self.status_var.set("Preparing file list...")

        self.scan_btn.config(state="disabled")
        self.browse_btn.config(state="disabled")

        self.queue = queue.Queue()
        self.scan_thread = threading.Thread(target=scan_folder, args=(path, self.queue), daemon=True)
        self.scan_thread.start()
        self.root.after(60, self.process_events)

    def process_events(self) -> None:
        if self.queue is None:
            return

        should_continue = True
        while True:
            try:
                event = self.queue.get_nowait()
            except queue.Empty:
                break

            event_type = event[0]

            if event_type == "start":
                total = event[1]
                self.progress.configure(maximum=total if total > 0 else 1)
                self.progress_var.set(0)
                self.status_var.set(f"Scanning started. Files found: {total}")
            elif event_type == "progress":
                current, total, filename = event[1], event[2], event[3]
                self.progress_var.set(current)
                self.status_var.set(f"Scanning {current}/{total}: {filename}")
            elif event_type == "done":
                self.render_results(event[1])
                should_continue = False
            elif event_type == "error":
                self.status_var.set(event[1])
                messagebox.showerror("Scan error", event[1])
                should_continue = False

        if should_continue:
            self.root.after(60, self.process_events)
        else:
            self.scan_btn.config(state="normal")
            self.browse_btn.config(state="normal")

    def clear_tables(self) -> None:
        for tree in (self.threats_tree, self.duplicates_tree, self.size_tree):
            for item in tree.get_children():
                tree.delete(item)

    def _reset_counts(self) -> None:
        self.counts = {
            "total": 0,
            "safe": 0,
            "warning": 0,
            "danger": 0,
            "duplicates": 0,
            "errors": 0,
        }
        self._refresh_summary_labels()

    def _refresh_summary_labels(self) -> None:
        texts = self.translations[self.language_var.get()]
        self.total_label_var.set(texts["summary_total"].format(count=self.counts["total"]))
        self.safe_label_var.set(texts["summary_safe"].format(count=self.counts["safe"]))
        self.warning_label_var.set(texts["summary_warning"].format(count=self.counts["warning"]))
        self.danger_label_var.set(texts["summary_danger"].format(count=self.counts["danger"]))
        self.duplicate_label_var.set(
            texts["summary_duplicates"].format(count=self.counts["duplicates"])
        )
        self.error_label_var.set(texts["summary_errors"].format(count=self.counts["errors"]))

    def _apply_theme(self) -> None:
        self._setup_style()
        # Update tag colors based on new palette
        self.threats_tree.tag_configure("safe", foreground=self.palette["safe"])
        self.threats_tree.tag_configure("warning", foreground=self.palette["warning"])
        self.threats_tree.tag_configure("danger", foreground=self.palette["danger"])
        self.threats_tree.tag_configure("resolved", foreground="#64748b")
        self._apply_menu_theme()

    def _apply_menu_theme(self) -> None:
        if not hasattr(self, "threat_menu"):
            return
        if self.theme_var.get() == "Dark":
            self.threat_menu.configure(
                background=self.palette["card"],
                foreground=self.palette["text"],
                activebackground="#141b2a",
                activeforeground=self.palette["text"],
                borderwidth=0,
            )
        else:
            self.threat_menu.configure(
                background="white",
                foreground="#0f172a",
                activebackground="#e2e8f0",
                activeforeground="#0f172a",
                borderwidth=0,
            )

    def _apply_language(self) -> None:
        texts = self.translations[self.language_var.get()]
        # Window title and header
        self.root.title(texts["title"])
        self.header_title_label.configure(text=texts["header_title"])
        self.header_subtitle_label.configure(text=texts["header_subtitle"])

        # Controls
        for child in self.main_frame.winfo_children():
            # Header label for folder is the first label in controls frame
            pass
        # Simpler: reconfigure known widgets directly
        # Folder label: find by grid position (0,0) in controls frame
        # To keep code simple and explicit, store the label when building layout
        # (added attribute in _build_layout)

        # Summary labels
        self._refresh_summary_labels()

        # Tabs
        if hasattr(self, "notebook"):
            self.notebook.tab(self.threats_tab, text=texts["tab_threats"])
            self.notebook.tab(self.duplicates_tab, text=texts["tab_duplicates"])
            self.notebook.tab(self.size_tab, text=texts["tab_sizes"])

        # Buttons
        self.browse_btn.configure(text=texts["btn_browse"])
        self.scan_btn.configure(text=texts["btn_scan"])
        self.settings_btn.configure(text=texts["btn_settings"])

        # Status text only if it's still the initial one
        if not self.folder_var.get() and "scan" not in self.status_var.get().lower():
            self.status_var.set(texts["status_initial"])

    def open_settings(self) -> None:
        texts = self.translations[self.language_var.get()]

        window = tk.Toplevel(self.root)
        window.title(texts["settings_title"])
        window.transient(self.root)
        window.resizable(False, False)

        frame = ttk.Frame(window, padding=12)
        frame.pack(fill="both", expand=True)

        ttk.Label(frame, text=texts["settings_theme"]).grid(row=0, column=0, sticky="w", pady=(0, 6))
        theme_combo = ttk.Combobox(
            frame,
            values=["Light", "Dark"],
            state="readonly",
            textvariable=self.theme_var,
        )
        theme_combo.grid(row=0, column=1, sticky="ew", pady=(0, 6), padx=(8, 0))

        ttk.Label(frame, text=texts["settings_language"]).grid(
            row=1, column=0, sticky="w", pady=(0, 6)
        )
        language_combo = ttk.Combobox(
            frame,
            values=list(self.translations.keys()),
            state="readonly",
            textvariable=self.language_var,
        )
        language_combo.grid(row=1, column=1, sticky="ew", pady=(0, 6), padx=(8, 0))

        button_row = ttk.Frame(frame)
        button_row.grid(row=2, column=0, columnspan=2, pady=(10, 0), sticky="e")

        def apply_and_close() -> None:
            self._apply_theme()
            self._apply_language()
            window.destroy()

        apply_btn = ttk.Button(button_row, text=texts["settings_apply"], command=apply_and_close)
        apply_btn.pack(side="right", padx=(0, 6))

        close_btn = ttk.Button(button_row, text=texts["settings_close"], command=window.destroy)
        close_btn.pack(side="right")

        frame.columnconfigure(1, weight=1)

    def render_results(self, result: Dict[str, object]) -> None:
        total = result["total"]
        safe_files = result["safe"]
        warning_files = result["warning"]
        dangerous_files = result["dangerous"]
        duplicates = result["duplicates"]
        sizes = result["sizes"]
        errors = result["errors"]

        self.counts = {
            "total": int(total),
            "safe": len(safe_files),
            "warning": len(warning_files),
            "danger": len(dangerous_files),
            "duplicates": len(duplicates),
            "errors": len(errors),
        }
        self._refresh_summary_labels()

        self._render_threats(safe_files, warning_files, dangerous_files)
        self._render_duplicates(duplicates)
        self._render_sizes(sizes)

        elapsed = result["elapsed"]
        self.status_var.set(
            f"Scan completed in {elapsed:.2f}s. Warnings: {len(warning_files)}, danger files: {len(dangerous_files)}"
        )

        if errors:
            messagebox.showwarning(
                "Completed with errors",
                f"Scan completed, but {len(errors)} files were skipped due to access/read issues.",
            )

    def _render_threats(
        self,
        safe_files: List[Path],
        warning_files: List[Path],
        dangerous_files: List[Path],
    ) -> None:
        shown = 0

        for file_path in dangerous_files:
            if shown >= MAX_ROWS_PER_TABLE:
                break
            self.threats_tree.insert(
                "",
                "end",
                values=("DANGER", str(file_path), "Multiple extensions detected"),
                tags=("danger",),
            )
            shown += 1

        for file_path in warning_files:
            if shown >= MAX_ROWS_PER_TABLE:
                break
            self.threats_tree.insert(
                "",
                "end",
                values=("WARNING", str(file_path), f"Suspicious extension: {file_path.suffix}"),
                tags=("warning",),
            )
            shown += 1

        for file_path in safe_files:
            if shown >= MAX_ROWS_PER_TABLE:
                break
            self.threats_tree.insert(
                "",
                "end",
                values=("SAFE", str(file_path), "No suspicious pattern"),
                tags=("safe",),
            )
            shown += 1

        total_threat_rows = len(dangerous_files) + len(warning_files) + len(safe_files)
        if total_threat_rows > MAX_ROWS_PER_TABLE:
            self.threats_tree.insert(
                "",
                "end",
                values=("INFO", "...", f"Showing first {MAX_ROWS_PER_TABLE} rows of {total_threat_rows}"),
            )

    def _render_duplicates(self, duplicates: Dict[str, List[Path]]) -> None:
        shown = 0
        for hash_value, files in duplicates.items():
            if shown >= MAX_ROWS_PER_TABLE:
                break

            examples = " | ".join(str(file_path) for file_path in files[:3])
            if len(files) > 3:
                examples += " | ..."

            self.duplicates_tree.insert(
                "",
                "end",
                values=(hash_value[:20], len(files), examples),
            )
            shown += 1

        if len(duplicates) > MAX_ROWS_PER_TABLE:
            self.duplicates_tree.insert(
                "",
                "end",
                values=("...", "...", f"Showing first {MAX_ROWS_PER_TABLE} duplicate groups"),
            )

    def _render_sizes(self, sizes: List[Tuple[Path, int]]) -> None:
        shown = 0
        for file_path, size in sizes:
            if shown >= MAX_ROWS_PER_TABLE:
                break
            self.size_tree.insert("", "end", values=(str(file_path), human_size(size)))
            shown += 1

        if len(sizes) > MAX_ROWS_PER_TABLE:
            self.size_tree.insert(
                "",
                "end",
                values=("...", f"Showing first {MAX_ROWS_PER_TABLE} files"),
            )

    def _item_risk(self, item_id: str) -> Optional[Tuple[str, Path]]:
        if not self.threats_tree.exists(item_id):
            return None

        values = self.threats_tree.item(item_id, "values")
        if len(values) < 2:
            return None

        status = str(values[0]).upper()
        file_path = Path(str(values[1]))
        if status not in {"WARNING", "DANGER"}:
            return None
        return status, file_path

    def on_threat_double_click(self, event: tk.Event) -> None:
        item_id = self.threats_tree.identify_row(event.y)
        if not item_id:
            return
        if self._item_risk(item_id) is None:
            return
        self.active_threat_item = item_id
        self.threat_menu.tk_popup(event.x_root, event.y_root)
        self.threat_menu.grab_release()

    def on_threat_context_menu(self, event: tk.Event) -> None:
        item_id = self.threats_tree.identify_row(event.y)
        if not item_id:
            return
        if self._item_risk(item_id) is None:
            return
        self.threats_tree.selection_set(item_id)
        self.active_threat_item = item_id
        self.threat_menu.tk_popup(event.x_root, event.y_root)
        self.threat_menu.grab_release()

    def apply_threat_action(self, action: str) -> None:
        if not self.active_threat_item:
            return
        payload = self._item_risk(self.active_threat_item)
        if payload is None:
            return

        status, file_path = payload
        note = ""

        try:
            if action == "quarantine":
                destination = self._move_to_quarantine(file_path)
                note = f"Moved to quarantine: {destination}"
            elif action == "delete":
                confirmed = messagebox.askyesno(
                    "Delete file",
                    f"Delete this file permanently?\n\n{file_path}",
                )
                if not confirmed:
                    return
                file_path.unlink()
                note = "Deleted by user"
            elif action == "open_location":
                self._open_file_location(file_path)
                self.status_var.set(f"Opened location for: {file_path.name}")
                return
            elif action == "ignore":
                note = "Ignored by user"
            else:
                return
        except (PermissionError, OSError) as error:
            messagebox.showerror("Action failed", f"Could not complete action:\n{error}")
            return

        self._mark_item_resolved(self.active_threat_item, status, file_path, note)

    def _mark_item_resolved(self, item_id: str, status: str, file_path: Path, note: str) -> None:
        if not self.threats_tree.exists(item_id):
            return

        self.threats_tree.item(
            item_id,
            values=("RESOLVED", str(file_path), note),
            tags=("resolved",),
        )

        if status == "WARNING" and self.counts["warning"] > 0:
            self.counts["warning"] -= 1
        if status == "DANGER" and self.counts["danger"] > 0:
            self.counts["danger"] -= 1
        self._refresh_summary_labels()
        self.status_var.set(f"Action completed: {note}")

    def _move_to_quarantine(self, file_path: Path) -> Path:
        root_folder = Path(self.folder_var.get()).resolve()
        quarantine_dir = root_folder / "_quarantine"
        quarantine_dir.mkdir(parents=True, exist_ok=True)

        destination = self._unique_destination(quarantine_dir, file_path.name)
        shutil.move(str(file_path), str(destination))
        return destination

    def _unique_destination(self, directory: Path, filename: str) -> Path:
        candidate = directory / filename
        counter = 1
        while candidate.exists():
            candidate = directory / f"{filename}.{counter}"
            counter += 1
        return candidate

    def _open_file_location(self, file_path: Path) -> None:
        if sys.platform == "darwin":
            subprocess.run(["open", "-R", str(file_path)], check=False)
            return
        if os.name == "nt":
            subprocess.run(["explorer", "/select,", str(file_path)], check=False)
            return
        subprocess.run(["xdg-open", str(file_path.parent)], check=False)


def main() -> None:
    root = tk.Tk()
    app = AntivirusVisualApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
