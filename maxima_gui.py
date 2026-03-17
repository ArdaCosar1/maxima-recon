#!/usr/bin/env python3
"""
Maxima Recon Framework v11.0 — Tkinter GUI
"""

import sys
import os
import io
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
from datetime import datetime

# Proje kokunu path'e ekle
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from maxima import (
    MENU, MENU_GROUPS, SCAN_PROFILES,
    run_module, run_scan_profile, run_full_scan,
    _generate_reports, save_json, VERSION,
)


# ── stdout yonlendirici ─────────────────────────────────────
class TextRedirector(io.TextIOBase):
    """stdout/stderr'i tkinter Text widget'ina yonlendirir (thread-safe)."""

    def __init__(self, widget: scrolledtext.ScrolledText):
        super().__init__()
        self.widget = widget

    def write(self, text: str):
        if not text:
            return 0
        self.widget.after(0, self._append, text)
        return len(text)

    def _append(self, text: str):
        self.widget.configure(state="normal")
        self.widget.insert(tk.END, text)
        self.widget.see(tk.END)
        self.widget.configure(state="disabled")

    def flush(self):
        pass


# ── Ana GUI Sinifi ───────────────────────────────────────────
class MaximaGUI:
    # Renk paleti
    BG = "#1a1a2e"
    BG2 = "#16213e"
    FG = "#e0e0e0"
    ACCENT = "#0f3460"
    HIGHLIGHT = "#e94560"
    GREEN = "#00c853"
    CYAN = "#4fc3f7"
    YELLOW = "#fdd835"
    MAGENTA = "#ce93d8"

    PROFILE_COLORS = {
        "web": "#66bb6a",
        "osint": "#4fc3f7",
        "vuln": "#ef5350",
        "network": "#42a5f5",
        "full": "#fdd835",
        "full-v2": "#ce93d8",
    }

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(f"Maxima Recon Framework v{VERSION}")
        self.root.geometry("920x720")
        self.root.minsize(800, 600)
        self.root.configure(bg=self.BG)

        self.results_store: dict = {}
        self.running = False

        self._setup_style()
        self._build_ui()

        # stdout/stderr yonlendirmesi
        self._orig_stdout = sys.stdout
        self._orig_stderr = sys.stderr
        self._redirector = TextRedirector(self.output_text)
        sys.stdout = self._redirector
        sys.stderr = self._redirector

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    # ── ttk style ────────────────────────────────────────────
    def _setup_style(self):
        style = ttk.Style()
        style.theme_use("clam")

        style.configure(".", background=self.BG, foreground=self.FG,
                         fieldbackground=self.BG2, font=("Consolas", 10))
        style.configure("TFrame", background=self.BG)
        style.configure("TLabel", background=self.BG, foreground=self.FG,
                         font=("Consolas", 10))
        style.configure("TButton", background=self.ACCENT, foreground=self.FG,
                         font=("Consolas", 10, "bold"), padding=6)
        style.map("TButton",
                  background=[("active", self.HIGHLIGHT), ("disabled", "#333")])
        style.configure("TEntry", fieldbackground=self.BG2, foreground=self.FG,
                         insertcolor=self.FG, font=("Consolas", 11))
        style.configure("Treeview", background=self.BG2, foreground=self.FG,
                         fieldbackground=self.BG2, font=("Consolas", 10),
                         rowheight=22)
        style.configure("Treeview.Heading", background=self.ACCENT,
                         foreground=self.FG, font=("Consolas", 10, "bold"))
        style.map("Treeview", background=[("selected", self.ACCENT)],
                  foreground=[("selected", "#fff")])
        style.configure("TLabelframe", background=self.BG, foreground=self.CYAN)
        style.configure("TLabelframe.Label", background=self.BG,
                         foreground=self.CYAN, font=("Consolas", 10, "bold"))

        # Profil butonlari icin ozel stiller
        for key, color in self.PROFILE_COLORS.items():
            style.configure(f"{key}.TButton", background=self.ACCENT,
                             foreground=color, font=("Consolas", 9, "bold"),
                             padding=4)
            style.map(f"{key}.TButton",
                      background=[("active", self.HIGHLIGHT)])

        style.configure("Run.TButton", background="#1b5e20", foreground=self.GREEN,
                         font=("Consolas", 11, "bold"), padding=8)
        style.map("Run.TButton",
                  background=[("active", "#2e7d32"), ("disabled", "#333")])

        style.configure("Status.TLabel", background=self.BG2, foreground=self.CYAN,
                         font=("Consolas", 9), padding=4)

    # ── UI bilesenlerini olustur ─────────────────────────────
    def _build_ui(self):
        # ── Ust: Hedef girisi ──
        top = ttk.Frame(self.root)
        top.pack(fill=tk.X, padx=8, pady=(8, 4))

        ttk.Label(top, text="Hedef URL / IP:", font=("Consolas", 11, "bold"),
                  foreground=self.CYAN).pack(side=tk.LEFT, padx=(0, 6))
        self.target_var = tk.StringVar()
        entry = ttk.Entry(top, textvariable=self.target_var, width=52)
        entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 6))
        entry.bind("<Return>", lambda e: self._run_selected())

        ttk.Label(top, text="Timeout:", foreground=self.YELLOW).pack(side=tk.LEFT, padx=(6, 2))
        self.timeout_var = tk.StringVar(value="8")
        ttk.Entry(top, textvariable=self.timeout_var, width=4).pack(side=tk.LEFT)

        # ── Orta: Bolunmus panel ──
        paned = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=8, pady=4)

        # Sol: Modul agaci + profil butonlari
        left = ttk.Frame(paned)
        paned.add(left, weight=1)

        # Modul agaci
        tree_frame = ttk.LabelFrame(left, text="  Moduller  ")
        tree_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 4))

        self.tree = ttk.Treeview(tree_frame, selectmode="extended", show="tree")
        tree_sb = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=tree_sb.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tree_sb.pack(side=tk.RIGHT, fill=tk.Y)

        self._populate_tree()

        # Profil butonlari
        prof_frame = ttk.LabelFrame(left, text="  Tarama Profilleri  ")
        prof_frame.pack(fill=tk.X, pady=(0, 4))

        profile_labels = {
            "web": "Web", "osint": "OSINT", "vuln": "Zafiyet",
            "network": "Ag", "full": "Tam (v1)", "full-v2": "Tam (v2)",
        }
        btn_row = ttk.Frame(prof_frame)
        btn_row.pack(fill=tk.X, padx=4, pady=4)
        for i, key in enumerate(SCAN_PROFILES):
            label = profile_labels.get(key, key)
            b = ttk.Button(btn_row, text=label, style=f"{key}.TButton",
                           command=lambda k=key: self._run_profile(k))
            b.grid(row=i // 3, column=i % 3, sticky="ew", padx=2, pady=2)
        for c in range(3):
            btn_row.columnconfigure(c, weight=1)

        # Calistir butonlari
        run_frame = ttk.Frame(left)
        run_frame.pack(fill=tk.X)

        self.btn_run = ttk.Button(run_frame, text="Secileni Calistir",
                                   style="Run.TButton", command=self._run_selected)
        self.btn_run.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 2))

        self.btn_run_all = ttk.Button(run_frame, text="Tumunu Calistir",
                                       style="Run.TButton", command=self._run_all)
        self.btn_run_all.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(2, 0))

        # Sag: Cikti alani
        right = ttk.Frame(paned)
        paned.add(right, weight=2)

        output_frame = ttk.LabelFrame(right, text="  Tarama Ciktisi  ")
        output_frame.pack(fill=tk.BOTH, expand=True)

        self.output_text = scrolledtext.ScrolledText(
            output_frame, wrap=tk.WORD, state="disabled",
            bg="#0d1117", fg="#c9d1d9", insertbackground="#c9d1d9",
            font=("Consolas", 10), relief=tk.FLAT, borderwidth=0,
        )
        self.output_text.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)

        # Cikti butonlari
        out_btns = ttk.Frame(right)
        out_btns.pack(fill=tk.X, pady=(4, 0))

        ttk.Button(out_btns, text="Rapor Kaydet",
                   command=self._save_report).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(out_btns, text="JSON Kaydet",
                   command=self._save_json).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(out_btns, text="Ciktiyi Temizle",
                   command=self._clear_output).pack(side=tk.RIGHT)

        # ── Alt: Durum cubugu ──
        self.status_var = tk.StringVar(value="Hazir.")
        status_bar = ttk.Label(self.root, textvariable=self.status_var,
                               style="Status.TLabel", anchor=tk.W)
        status_bar.pack(fill=tk.X, padx=8, pady=(0, 6))

    # ── Modul agacini doldur ─────────────────────────────────
    def _populate_tree(self):
        group_colors = {
            "Web Scanners": self.GREEN,
            "OSINT & Info": self.CYAN,
            "Advanced Modules": self.YELLOW,
            "v2 Modules": self.MAGENTA,
        }
        for gname, _gcol, gmods in MENU_GROUPS:
            gid = self.tree.insert("", tk.END, text=f"  {gname}", open=True)
            # Tag renklendirmesi
            color = group_colors.get(gname, self.FG)
            self.tree.tag_configure(f"grp_{gname}", foreground=color)
            self.tree.item(gid, tags=(f"grp_{gname}",))
            for mid, (mname, _cls, _tags) in gmods.items():
                iid = self.tree.insert(gid, tk.END, text=f"  [{mid:2d}] {mname}",
                                       values=(mid,))
                self.tree.tag_configure(f"mod_{mid}", foreground=self.FG)
                self.tree.item(iid, tags=(f"mod_{mid}",))

    # ── Secili modulleri al ──────────────────────────────────
    def _get_selected_modules(self) -> list:
        mods = []
        for iid in self.tree.selection():
            vals = self.tree.item(iid, "values")
            if vals and vals[0]:
                try:
                    mods.append(int(vals[0]))
                except (ValueError, IndexError):
                    pass
            else:
                # Grup secildi — altindaki tum modulleri ekle
                for child in self.tree.get_children(iid):
                    cv = self.tree.item(child, "values")
                    if cv and cv[0]:
                        try:
                            mods.append(int(cv[0]))
                        except (ValueError, IndexError):
                            pass
        return sorted(set(mods))

    # ── Hedef dogrulama ──────────────────────────────────────
    def _validate_target(self):
        target = self.target_var.get().strip()
        if not target:
            messagebox.showwarning("Hedef Gerekli", "Lutfen bir hedef URL veya IP adresi girin.")
            return None
        return target

    def _get_timeout(self) -> int:
        try:
            return max(1, int(self.timeout_var.get()))
        except ValueError:
            return 8

    # ── Tarama baslatma yardimcisi (thread) ──────────────────
    def _set_running(self, state: bool):
        self.running = state
        s = "disabled" if state else "!disabled"
        self.btn_run.state([s])
        self.btn_run_all.state([s])
        if state:
            self.status_var.set("Tarama devam ediyor...")
        else:
            self.status_var.set(f"Tamamlandi. ({len(self.results_store)} modul sonucu)")

    def _run_in_thread(self, func, *args):
        if self.running:
            return

        def wrapper():
            self.root.after(0, self._set_running, True)
            try:
                func(*args)
            except Exception as exc:
                print(f"\n[HATA] {exc}")
            finally:
                self.root.after(0, self._set_running, False)

        t = threading.Thread(target=wrapper, daemon=True)
        t.start()

    # ── Calistirma komutlari ─────────────────────────────────
    def _run_selected(self):
        target = self._validate_target()
        if not target:
            return
        mods = self._get_selected_modules()
        if not mods:
            messagebox.showinfo("Modul Secimi", "Lutfen listeden en az bir modul secin.")
            return
        timeout = self._get_timeout()

        def task():
            for mid in mods:
                run_module(mid, target, self.results_store, timeout=timeout)

        self._run_in_thread(task)

    def _run_all(self):
        target = self._validate_target()
        if not target:
            return
        timeout = self._get_timeout()
        self._run_in_thread(run_full_scan, target, self.results_store, timeout)

    def _run_profile(self, profile_key: str):
        target = self._validate_target()
        if not target:
            return
        timeout = self._get_timeout()
        self._run_in_thread(run_scan_profile, profile_key, target,
                            self.results_store, timeout)

    # ── Rapor / JSON kaydet ──────────────────────────────────
    def _make_output_dir(self) -> str:
        target = self.target_var.get().strip() or "bilinmeyen"
        safe = target.replace("://", "_").replace("/", "_").replace(":", "_")
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        d = os.path.join("maxima_reports", f"{safe}_{ts}")
        os.makedirs(d, exist_ok=True)
        return d

    def _save_report(self):
        if not self.results_store:
            messagebox.showinfo("Sonuc Yok", "Henuz tarama sonucu bulunmuyor.")
            return
        target = self.target_var.get().strip() or "bilinmeyen"
        out_dir = self._make_output_dir()

        def task():
            _generate_reports(target, self.results_store, out_dir)
            print(f"\n[+] Raporlar kaydedildi: {out_dir}")

        self._run_in_thread(task)

    def _save_json(self):
        if not self.results_store:
            messagebox.showinfo("Sonuc Yok", "Henuz tarama sonucu bulunmuyor.")
            return
        target = self.target_var.get().strip() or "bilinmeyen"
        out_dir = self._make_output_dir()
        path = save_json(self.results_store, out_dir, target)
        print(f"\n[+] JSON rapor kaydedildi: {path}")
        self.status_var.set(f"JSON kaydedildi: {path}")

    # ── Ciktiyi temizle ──────────────────────────────────────
    def _clear_output(self):
        self.output_text.configure(state="normal")
        self.output_text.delete("1.0", tk.END)
        self.output_text.configure(state="disabled")
        self.results_store.clear()
        self.status_var.set("Cikti temizlendi.")

    # ── Kapatma ──────────────────────────────────────────────
    def _on_close(self):
        sys.stdout = self._orig_stdout
        sys.stderr = self._orig_stderr
        self.root.destroy()


# ── Giris noktasi ────────────────────────────────────────────
def main():
    root = tk.Tk()
    # Ikon ayari (varsa)
    try:
        icon_path = os.path.join(os.path.dirname(__file__), "maxima.ico")
        if os.path.isfile(icon_path):
            root.iconbitmap(icon_path)
    except Exception:
        pass
    MaximaGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
