# Searchable Encryption Lab

Desktop Python application for experimenting with searchable encryption, leakage analysis, and performance/privacy trade-offs for keyword search.

## Overview

The project provides a `tkinter` GUI that lets you:

- import `.txt` documents;
- generate a synthetic document corpus;
- extract keywords from documents;
- build a protected index in `SQLite`;
- search by keyword under multiple protection modes;
- measure `T_index_ms`, `T_search_ms`, `Padding_overhead_%`, and `Leakage_score`;
- compare search modes and export metrics to CSV;
- plot results with `matplotlib` if installed.

## Supported Modes

- `no_protection`
  Stores the keyword in the index without protection.

- `padding`
  Hashes the keyword and simulates padded result sizes to the next power of two.

- `padding+batching+epoch`
  Adds epoch-based hashing, padding, and fixed-size batched retrieval.

## Tech Stack

- Python
- `tkinter` for the desktop UI
- `sqlite3` for local persistence
- `matplotlib` for charts (optional)

## Project Structure

- [searchable_encryption.py](C:\Users\User\PycharmProjects\Searchable_encryption\main.py) - application entry point, UI, indexing, search, and metrics logic
- [secure_index.db](C:\Users\User\PycharmProjects\Searchable_encryption\secure_index.db) - local SQLite database for encrypted documents and index entries

## Running the App

1. Activate your virtual environment if you use one.
2. Install `matplotlib` if you want chart generation:

```powershell
pip install matplotlib
```

3. Start the application:

```powershell
python searchable_encryption.py
```

## Application Workflow

### 1. Import

- `Load/Import TXT` loads `.txt` files from disk.
- `Generate 1000 docs` creates a synthetic corpus for testing.
- `Clear corpus` removes all currently loaded documents from memory.

### 2. Build Index

- `Build protected index` encrypts document content and rebuilds the index.
- `Show index size` reports the current `secure_index.db` size.

### 3. Search

- enter a keyword;
- use `Search` for a single query;
- use `Run benchmark (50 queries)` for repeated random search tests.

### 4. Leakage

- `Leakage analysis` computes correlation between real and observed results;
- `Compare modes` runs the same test flow across all supported modes.

### 5. Metrics / Export

- `Export CSV` writes mode comparison results to a `.csv` file;
- `Generate charts` displays leakage, search time, and padding overhead charts.

## Data Model

The SQLite database contains two tables:

- `documents` - `doc_id`, encrypted content, `epoch_id`
- `index_entries` - token, `doc_id`, `epoch_id`

The database file is stored locally as `secure_index.db`.

## Notes and Limitations

- The encryption logic is a lightweight demo and is not suitable for production use.
- Keyword extraction is frequency-based and uses a stopword list.
- The application is designed for lab experiments, visualization, and comparative evaluation rather than real secure deployment.

## Typical Flow

1. Import or generate documents.
2. Select a protection mode.
3. Build the index.
4. Run search or benchmark tests.
5. Inspect leakage metrics.
6. Compare modes and export results.
