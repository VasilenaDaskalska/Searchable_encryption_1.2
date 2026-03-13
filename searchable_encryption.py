import base64
import csv
import hashlib
import math
import os
import random
import re
import sqlite3
import string
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

try:
    import matplotlib.pyplot as plt
except Exception:
    plt = None


DB_PATH = Path("secure_index.db")
DEFAULT_EPOCH = 1

STOPWORDS = {
    "the", "and", "is", "in", "to", "of", "a", "for", "on", "with", "as", "by", "an", "at", "or",
    "that", "this", "it", "be", "from", "are", "was", "were", "but", "not", "can", "will", "we", "you",
    "i", "he", "she", "they", "them", "our", "your", "their", "about", "into", "over", "under", "after",
    "before", "during", "through", "without", "within", "more", "most", "some", "any", "all", "each", "other",
    "и", "в", "на", "за", "с", "по", "че", "не", "се", "са", "как", "от", "до", "при", "или", "а", "но",
}


def now_ms() -> float:
    return time.perf_counter() * 1000.0


def normalize_text(text: str) -> str:
    return " ".join(text.lower().split())


def extract_keywords(text: str, top_k: int = 20) -> List[str]:
    words = re.findall(r"[a-zA-Zа-яА-Я0-9]+", text.lower())
    filtered = [w for w in words if len(w) > 2 and w not in STOPWORDS]
    freq = Counter(filtered)
    return [w for w, _ in freq.most_common(top_k)]


def power2_pad_size(real_count: int) -> int:
    if real_count <= 0:
        return 0
    return 2 ** math.ceil(math.log2(real_count))


def padding_overhead_percent(real_count: int, padded_count: int) -> float:
    if real_count <= 0:
        return 0.0
    return ((padded_count - real_count) / real_count) * 100.0


def correlation(a: List[float], b: List[float]) -> float:
    if len(a) != len(b) or len(a) < 2:
        return 0.0
    mean_a = sum(a) / len(a)
    mean_b = sum(b) / len(b)
    da = [x - mean_a for x in a]
    db = [y - mean_b for y in b]
    num = sum(x * y for x, y in zip(da, db))
    den_a = math.sqrt(sum(x * x for x in da))
    den_b = math.sqrt(sum(y * y for y in db))
    if den_a == 0 or den_b == 0:
        return 0.0
    return max(0.0, min(1.0, num / (den_a * den_b)))


def encrypt_text(plain: str, key: str) -> str:
    # Lightweight XOR stream with SHA256-derived bytes for demo purposes.
    key_stream = hashlib.sha256(key.encode("utf-8")).digest()
    src = plain.encode("utf-8")
    out = bytes(src[i] ^ key_stream[i % len(key_stream)] for i in range(len(src)))
    return base64.b64encode(out).decode("ascii")


@dataclass
class SearchStats:
    mode: str
    keyword: str
    real_count: int
    padded_count: int
    returned_count: int
    t_search_ms: float
    padding_overhead_percent: float


class SearchableEncryptionApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Searchable Encryption Lab")
        self.root.geometry("1250x820")

        self.documents: Dict[int, str] = {}
        self.doc_keywords: Dict[int, List[str]] = {}
        self.current_epoch = DEFAULT_EPOCH
        self.secret_key = "demo-secret-key"

        self.search_logs: Dict[str, List[Tuple[int, int]]] = defaultdict(list)
        self.mode_results: List[Dict[str, float]] = []

        self._build_ui()
        self._init_db()

    def _build_ui(self):
        cfg = ttk.Frame(self.root, padding=8)
        cfg.pack(fill="x")

        ttk.Label(cfg, text="Режим:").pack(side="left")
        self.mode_var = tk.StringVar(value="no_protection")
        ttk.Combobox(
            cfg,
            textvariable=self.mode_var,
            values=["no_protection", "padding", "padding+batching+epoch"],
            width=28,
            state="readonly",
        ).pack(side="left", padx=6)

        ttk.Label(cfg, text="Batch size:").pack(side="left")
        self.batch_size_var = tk.IntVar(value=8)
        ttk.Spinbox(cfg, from_=1, to=200, textvariable=self.batch_size_var, width=6).pack(side="left", padx=6)

        ttk.Label(cfg, text="Top keywords/doc:").pack(side="left")
        self.top_k_var = tk.IntVar(value=15)
        ttk.Spinbox(cfg, from_=3, to=50, textvariable=self.top_k_var, width=6).pack(side="left", padx=6)

        ttk.Button(cfg, text="Epoch +1", command=self.rotate_epoch).pack(side="left", padx=10)
        self.epoch_lbl = ttk.Label(cfg, text=f"Текущ epoch_id: {self.current_epoch}")
        self.epoch_lbl.pack(side="left")

        tabs = ttk.Notebook(self.root)
        tabs.pack(fill="both", expand=True, padx=8, pady=6)

        self.tab_import = ttk.Frame(tabs)
        self.tab_build = ttk.Frame(tabs)
        self.tab_search = ttk.Frame(tabs)
        self.tab_leakage = ttk.Frame(tabs)
        self.tab_results = ttk.Frame(tabs)

        tabs.add(self.tab_import, text="4.1 Import")
        tabs.add(self.tab_build, text="4.2 Build Index")
        tabs.add(self.tab_search, text="4.3 Search")
        tabs.add(self.tab_leakage, text="4.4 Leakage")
        tabs.add(self.tab_results, text="Метрики/Експорт")

        self._build_import_tab()
        self._build_index_tab()
        self._build_search_tab()
        self._build_leakage_tab()
        self._build_results_tab()

        log_box = ttk.LabelFrame(self.root, text="Лог", padding=6)
        log_box.pack(fill="both", expand=False, padx=8, pady=(0, 8))
        self.log = tk.Text(log_box, height=9, wrap="word")
        self.log.pack(fill="both", expand=True)

    def _build_import_tab(self):
        f = self.tab_import
        bar = ttk.Frame(f, padding=8)
        bar.pack(fill="x")

        ttk.Button(bar, text="Зареди/Импорт TXT", command=self.import_documents).pack(side="left", padx=4)
        ttk.Button(bar, text="Генерирай 1000 docs", command=lambda: self.generate_corpus(1000)).pack(side="left", padx=4)
        ttk.Button(bar, text="Изчисти corpus", command=self.clear_corpus).pack(side="left", padx=4)

        self.docs_info_var = tk.StringVar(value="Документи: 0")
        ttk.Label(bar, textvariable=self.docs_info_var).pack(side="left", padx=14)

        self.doc_preview = tk.Text(f, height=26, wrap="word")
        self.doc_preview.pack(fill="both", expand=True, padx=8, pady=8)

    def _build_index_tab(self):
        f = self.tab_build
        top = ttk.Frame(f, padding=8)
        top.pack(fill="x")

        ttk.Button(top, text="Build protected index", command=self.build_index).pack(side="left", padx=4)
        ttk.Button(top, text="Покажи размер на индекс", command=self.show_index_size).pack(side="left", padx=4)

        self.index_stats_var = tk.StringVar(value="T_index_ms: - | Index_size_MB: -")
        ttk.Label(f, textvariable=self.index_stats_var).pack(anchor="w", padx=12)

        self.index_preview = tk.Text(f, height=28, wrap="none")
        self.index_preview.pack(fill="both", expand=True, padx=8, pady=8)

    def _build_search_tab(self):
        f = self.tab_search
        row = ttk.Frame(f, padding=8)
        row.pack(fill="x")

        ttk.Label(row, text="Keyword:").pack(side="left")
        self.search_var = tk.StringVar()
        ttk.Entry(row, textvariable=self.search_var, width=32).pack(side="left", padx=6)

        ttk.Button(row, text="Search", command=self.search_keyword).pack(side="left", padx=4)
        ttk.Button(row, text="Изпълни тест (50 заявки)", command=self.run_search_benchmark).pack(side="left", padx=4)

        self.search_stats_var = tk.StringVar(value="T_search_ms: - | Padding_overhead_%: -")
        ttk.Label(f, textvariable=self.search_stats_var).pack(anchor="w", padx=12)

        self.search_output = tk.Text(f, height=27, wrap="word")
        self.search_output.pack(fill="both", expand=True, padx=8, pady=8)

    def _build_leakage_tab(self):
        f = self.tab_leakage
        bar = ttk.Frame(f, padding=8)
        bar.pack(fill="x")

        ttk.Button(bar, text="Leakage анализ", command=self.compute_leakage).pack(side="left", padx=4)
        ttk.Button(bar, text="Сравни режими", command=self.compare_modes).pack(side="left", padx=4)

        self.leakage_var = tk.StringVar(value="Leakage_score: -")
        ttk.Label(f, textvariable=self.leakage_var).pack(anchor="w", padx=12)

        self.leakage_text = tk.Text(f, height=27, wrap="word")
        self.leakage_text.pack(fill="both", expand=True, padx=8, pady=8)

    def _build_results_tab(self):
        f = self.tab_results
        top = ttk.Frame(f, padding=8)
        top.pack(fill="x")

        ttk.Button(top, text="Експорт CSV", command=self.export_csv).pack(side="left", padx=4)
        ttk.Button(top, text="Генерирай графики", command=self.plot_results).pack(side="left", padx=4)

        cols = (
            "mode", "num_docs", "T_index_ms", "T_search_ms", "Index_size_MB", "Padding_overhead_%", "Leakage_score"
        )
        self.tree = ttk.Treeview(f, columns=cols, show="headings", height=24)
        for c in cols:
            self.tree.heading(c, text=c)
            self.tree.column(c, width=150, anchor="center")
        self.tree.pack(fill="both", expand=True, padx=8, pady=8)

    def _init_db(self):
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS documents (
                doc_id INTEGER PRIMARY KEY,
                content_enc TEXT NOT NULL,
                epoch_id INTEGER NOT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS index_entries (
                token TEXT NOT NULL,
                doc_id INTEGER NOT NULL,
                epoch_id INTEGER NOT NULL
            )
            """
        )
        cur.execute("CREATE INDEX IF NOT EXISTS idx_token_epoch ON index_entries(token, epoch_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_doc ON index_entries(doc_id)")
        conn.commit()
        conn.close()

    def _db_clear(self):
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("DELETE FROM index_entries")
        cur.execute("DELETE FROM documents")
        conn.commit()
        conn.close()

    def _db_insert_document(self, doc_id: int, content_enc: str, epoch_id: int):
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("INSERT OR REPLACE INTO documents(doc_id, content_enc, epoch_id) VALUES(?,?,?)", (doc_id, content_enc, epoch_id))
        conn.commit()
        conn.close()

    def _db_insert_index_rows(self, rows: List[Tuple[str, int, int]]):
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.executemany("INSERT INTO index_entries(token, doc_id, epoch_id) VALUES(?,?,?)", rows)
        conn.commit()
        conn.close()

    def _query_docs_by_token(self, token: str, epoch_id: Optional[int] = None) -> List[int]:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        if epoch_id is None:
            cur.execute("SELECT doc_id FROM index_entries WHERE token=?", (token,))
        else:
            cur.execute("SELECT doc_id FROM index_entries WHERE token=? AND epoch_id=?", (token, epoch_id))
        rows = [r[0] for r in cur.fetchall()]
        conn.close()
        return rows

    def log_line(self, msg: str):
        ts = time.strftime("%H:%M:%S")
        self.log.insert("end", f"[{ts}] {msg}\n")
        self.log.see("end")

    def clear_corpus(self):
        self.documents.clear()
        self.doc_keywords.clear()
        self.docs_info_var.set("Документи: 0")
        self.doc_preview.delete("1.0", "end")
        self.log_line("Corpus изчистен.")

    def import_documents(self):
        paths = filedialog.askopenfilenames(title="Избери TXT документи", filetypes=[("Text files", "*.txt")])
        if not paths:
            return

        next_id = max(self.documents.keys(), default=0) + 1
        loaded = 0
        for p in paths:
            try:
                raw = Path(p).read_text(encoding="utf-8", errors="ignore")
                norm = normalize_text(raw)
                if not norm:
                    continue
                self.documents[next_id] = norm
                self.doc_keywords[next_id] = extract_keywords(norm, self.top_k_var.get())
                next_id += 1
                loaded += 1
            except Exception as exc:
                self.log_line(f"Грешка при {p}: {exc}")

        self.docs_info_var.set(f"Документи: {len(self.documents)}")
        self.render_doc_preview()
        self.log_line(f"Импортнати документи: {loaded}")

    def generate_corpus(self, n_docs: int = 1000):
        vocab = [
            "encryption", "search", "token", "padding", "batching", "epoch", "privacy", "database", "cloud", "query",
            "index", "secure", "client", "server", "keyword", "document", "analysis", "metric", "python", "sqlite",
            "alpha", "beta", "gamma", "delta", "signal", "noise", "vector", "model", "latency", "throughput",
        ]
        next_id = max(self.documents.keys(), default=0) + 1
        for _ in range(n_docs):
            words = [random.choice(vocab) for _ in range(random.randint(35, 120))]
            noise = ["".join(random.choices(string.ascii_lowercase, k=6)) for _ in range(random.randint(3, 10))]
            text = normalize_text(" ".join(words + noise))
            self.documents[next_id] = text
            self.doc_keywords[next_id] = extract_keywords(text, self.top_k_var.get())
            next_id += 1

        self.docs_info_var.set(f"Документи: {len(self.documents)}")
        self.render_doc_preview()
        self.log_line(f"Генерирани документи: {n_docs}")

    def render_doc_preview(self):
        self.doc_preview.delete("1.0", "end")
        for doc_id in sorted(self.documents.keys())[:20]:
            txt = self.documents[doc_id][:180]
            kws = ", ".join(self.doc_keywords.get(doc_id, [])[:8])
            self.doc_preview.insert("end", f"doc_id={doc_id}\n  text={txt}...\n  keywords={kws}\n\n")

    def keyword_to_token(self, keyword: str) -> str:
        mode = self.mode_var.get()
        if mode == "no_protection":
            return keyword
        payload = f"{keyword}|{self.secret_key}|{self.current_epoch if mode == 'padding+batching+epoch' else 0}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def build_index(self):
        if not self.documents:
            messagebox.showwarning("Липсват документи", "Импортирайте или генерирайте документи преди build.")
            return

        t0 = now_ms()
        self._db_clear()

        rows: List[Tuple[str, int, int]] = []
        for doc_id, text in self.documents.items():
            enc = encrypt_text(text, self.secret_key)
            self._db_insert_document(doc_id, enc, self.current_epoch)
            for kw in self.doc_keywords.get(doc_id, []):
                token = self.keyword_to_token(kw)
                rows.append((token, doc_id, self.current_epoch))

        self._db_insert_index_rows(rows)
        t1 = now_ms()
        t_index_ms = t1 - t0
        index_mb = self.get_index_size_mb()

        self.index_stats_var.set(f"T_index_ms: {t_index_ms:.2f} | Index_size_MB: {index_mb:.3f}")

        self.index_preview.delete("1.0", "end")
        sample = rows[:120]
        self.index_preview.insert("end", "(token, doc_id, epoch_id) sample:\n")
        for token, doc_id, epoch_id in sample:
            self.index_preview.insert("end", f"{token[:16]}... , {doc_id}, {epoch_id}\n")

        self.log_line(f"Build index готов: {len(rows)} index entries, T_index_ms={t_index_ms:.2f}")

    def get_index_size_mb(self) -> float:
        if not DB_PATH.exists():
            return 0.0
        return DB_PATH.stat().st_size / (1024 * 1024)

    def show_index_size(self):
        size = self.get_index_size_mb()
        self.log_line(f"Index_size_MB={size:.3f}")
        messagebox.showinfo("Index size", f"Index_size_MB = {size:.3f}")

    def _search_once(self, keyword: str, mode: Optional[str] = None) -> SearchStats:
        keyword = normalize_text(keyword)
        mode = mode or self.mode_var.get()

        if mode == "no_protection":
            token = keyword
            epoch = None
        elif mode == "padding":
            token = hashlib.sha256(f"{keyword}|{self.secret_key}|0".encode("utf-8")).hexdigest()
            epoch = None
        else:
            token = hashlib.sha256(f"{keyword}|{self.secret_key}|{self.current_epoch}".encode("utf-8")).hexdigest()
            epoch = self.current_epoch

        t0 = now_ms()
        doc_ids = self._query_docs_by_token(token, epoch)
        real_count = len(doc_ids)
        padded_count = real_count

        if mode in ("padding", "padding+batching+epoch"):
            padded_count = power2_pad_size(real_count)

        if mode == "padding+batching+epoch":
            batch_size = max(1, self.batch_size_var.get())
            # Simulate fixed-size batched retrieval.
            num_batches = math.ceil(max(1, padded_count) / batch_size)
            returned_count = num_batches * batch_size if real_count > 0 else 0
        else:
            returned_count = padded_count

        t1 = now_ms()
        t_ms = t1 - t0
        overhead = padding_overhead_percent(real_count, padded_count)

        self.search_logs[mode].append((real_count, returned_count))

        return SearchStats(
            mode=mode,
            keyword=keyword,
            real_count=real_count,
            padded_count=padded_count,
            returned_count=returned_count,
            t_search_ms=t_ms,
            padding_overhead_percent=overhead,
        )

    def search_keyword(self):
        kw = self.search_var.get().strip()
        if not kw:
            messagebox.showwarning("Празна заявка", "Въведете ключова дума.")
            return

        st = self._search_once(kw)
        self.search_stats_var.set(
            f"T_search_ms: {st.t_search_ms:.3f} | Padding_overhead_%: {st.padding_overhead_percent:.2f}"
        )

        self.search_output.delete("1.0", "end")
        self.search_output.insert("end", f"mode = {st.mode}\n")
        self.search_output.insert("end", f"keyword = {st.keyword}\n")
        self.search_output.insert("end", f"real_count = {st.real_count}\n")
        self.search_output.insert("end", f"padded_count = {st.padded_count}\n")
        self.search_output.insert("end", f"returned_count = {st.returned_count}\n")
        self.search_output.insert("end", f"T_search_ms = {st.t_search_ms:.4f}\n")
        self.search_output.insert("end", f"Padding_overhead_% = {st.padding_overhead_percent:.2f}\n")

        self.log_line(
            f"Search '{kw}' ({st.mode}): real={st.real_count}, padded={st.padded_count}, T_search_ms={st.t_search_ms:.3f}"
        )

    def run_search_benchmark(self, n_queries: int = 50):
        if not self.doc_keywords:
            messagebox.showwarning("Липсват данни", "Нужни са документи и индекс.")
            return

        all_kws = [kw for kws in self.doc_keywords.values() for kw in kws]
        if not all_kws:
            messagebox.showwarning("Липсват keywords", "Няма извлечени keywords.")
            return

        queries = [random.choice(all_kws) for _ in range(n_queries)]
        times = []
        overheads = []
        for q in queries:
            st = self._search_once(q)
            times.append(st.t_search_ms)
            overheads.append(st.padding_overhead_percent)

        avg_t = sum(times) / len(times)
        avg_ov = sum(overheads) / len(overheads)
        self.search_stats_var.set(f"T_search_ms(avg): {avg_t:.3f} | Padding_overhead_%(avg): {avg_ov:.2f}")
        self.log_line(f"Benchmark: {n_queries} заявки, avg T_search_ms={avg_t:.3f}, avg overhead={avg_ov:.2f}%")

    def compute_leakage(self):
        mode = self.mode_var.get()
        logs = self.search_logs.get(mode, [])
        if len(logs) < 2:
            messagebox.showinfo("Недостатъчни данни", "Изпълнете поне 2 търсения в този режим.")
            return

        real_freq = [x for x, _ in logs]
        observed_freq = [y for _, y in logs]
        score = correlation(real_freq, observed_freq)

        self.leakage_var.set(f"Leakage_score: {score:.4f}")
        self.leakage_text.delete("1.0", "end")
        self.leakage_text.insert("end", f"Mode: {mode}\n")
        self.leakage_text.insert("end", f"Leakage_score = corr(real_freq, observed_freq) = {score:.4f}\n")
        self.leakage_text.insert("end", f"Samples: {len(logs)}\n")
        self.leakage_text.insert("end", "\nПоследни 20 наблюдения (real -> observed):\n")
        for r, o in logs[-20:]:
            self.leakage_text.insert("end", f"{r} -> {o}\n")

        self.log_line(f"Leakage анализ ({mode}): score={score:.4f}")

    def compare_modes(self):
        if not self.documents:
            messagebox.showwarning("Липсват документи", "Генерирайте/импортирайте документи.")
            return

        modes = ["no_protection", "padding", "padding+batching+epoch"]
        all_kws = [kw for kws in self.doc_keywords.values() for kw in kws]
        if not all_kws:
            messagebox.showwarning("Липсват keywords", "Няма keywords за тест.")
            return

        self.mode_results.clear()
        self.tree.delete(*self.tree.get_children())

        for mode in modes:
            old_mode = self.mode_var.get()
            self.mode_var.set(mode)

            if mode == "padding+batching+epoch":
                self.rotate_epoch(silent=True)

            t0 = now_ms()
            self.build_index()
            t_index_ms = now_ms() - t0

            times = []
            overheads = []
            logs_local = []
            queries = [random.choice(all_kws) for _ in range(80)]
            for q in queries:
                st = self._search_once(q, mode=mode)
                times.append(st.t_search_ms)
                overheads.append(st.padding_overhead_percent)
                logs_local.append((st.real_count, st.returned_count))

            score = correlation([x for x, _ in logs_local], [y for _, y in logs_local])
            row = {
                "mode": mode,
                "num_docs": len(self.documents),
                "T_index_ms": round(t_index_ms, 2),
                "T_search_ms": round(sum(times) / len(times), 4),
                "Index_size_MB": round(self.get_index_size_mb(), 4),
                "Padding_overhead_%": round(sum(overheads) / len(overheads), 2),
                "Leakage_score": round(score, 4),
            }
            self.mode_results.append(row)
            self.tree.insert("", "end", values=tuple(row[c] for c in self.tree["columns"]))

            self.mode_var.set(old_mode)

        self.log_line("Сравнение по режими е завършено.")

    def export_csv(self):
        if not self.mode_results:
            messagebox.showwarning("Няма резултати", "Първо изпълнете 'Сравни режими'.")
            return

        path = filedialog.asksaveasfilename(
            title="Експорт CSV",
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv")],
            initialfile="results_metrics.csv",
        )
        if not path:
            return

        cols = ["mode", "num_docs", "T_index_ms", "T_search_ms", "Index_size_MB", "Padding_overhead_%", "Leakage_score"]
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=cols)
            w.writeheader()
            w.writerows(self.mode_results)

        self.log_line(f"CSV експорт: {path}")

    def plot_results(self):
        if plt is None:
            messagebox.showwarning("Matplotlib липсва", "Инсталирайте matplotlib за графики.")
            return
        if not self.mode_results:
            messagebox.showwarning("Няма резултати", "Първо изпълнете 'Сравни режими'.")
            return

        modes = [r["mode"] for r in self.mode_results]
        leakage = [r["Leakage_score"] for r in self.mode_results]
        tsearch = [r["T_search_ms"] for r in self.mode_results]
        overhead = [r["Padding_overhead_%"] for r in self.mode_results]

        fig, axes = plt.subplots(1, 3, figsize=(15, 4.5))

        axes[0].bar(modes, leakage, color=["#6b7280", "#f59e0b", "#2563eb"])
        axes[0].set_title("Leakage_score по режими")
        axes[0].set_ylim(0, 1)
        axes[0].tick_params(axis="x", rotation=20)

        axes[1].bar(modes, tsearch, color=["#6b7280", "#10b981", "#0ea5e9"])
        axes[1].set_title("T_search_ms по режими")
        axes[1].tick_params(axis="x", rotation=20)

        axes[2].bar(modes, overhead, color=["#6b7280", "#ef4444", "#8b5cf6"])
        axes[2].set_title("Padding_overhead_% по режими")
        axes[2].tick_params(axis="x", rotation=20)

        fig.tight_layout()
        plt.show()
        self.log_line("Графиките са визуализирани.")

    def rotate_epoch(self, silent: bool = False):
        self.current_epoch += 1
        self.epoch_lbl.configure(text=f"Текущ epoch_id: {self.current_epoch}")
        if not silent:
            self.log_line(f"Epoch rotation -> {self.current_epoch}")


def main():
    root = tk.Tk()
    app = SearchableEncryptionApp(root)
    app.log_line("Приложението е стартирано.")
    app.log_line("Стъпки: 1) Импорт/генериране 2) Build index 3) Search/Benchmark 4) Leakage 5) Compare/Export.")
    root.mainloop()


if __name__ == "__main__":
    main()
