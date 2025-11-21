#!/usr/bin/env python3

import hashlib
import json
import csv
import os
from datetime import datetime
import tkinter as tk
from tkinter import ttk
from tkinter import filedialog, messagebox

# ----------------- Configuration -----------------
LOG_DIR = 'logs'
JSON_LOG = os.path.join(LOG_DIR, 'checksum_log.json')
CSV_LOG = os.path.join(LOG_DIR, 'checksum_log.csv')
CHUNK_SIZE = 8192

# Ensure log directory exists
os.makedirs(LOG_DIR, exist_ok=True)

# ----------------- Utility Functions -----------------

def compute_hash(file_path: str, algorithm: str) -> str:
    """Compute hash of a file using the given algorithm.

    algorithm: one of 'md5','sha1','sha256'
    Returns hexadecimal digest string.
    """
    algo = algorithm.lower()
    if algo not in ('md5', 'sha1', 'sha256'):
        raise ValueError('Unsupported algorithm: ' + algorithm)

    if algo == 'md5':
        h = hashlib.md5()
    elif algo == 'sha1':
        h = hashlib.sha1()
    else:
        h = hashlib.sha256()

    with open(file_path, 'rb') as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def log_result(entry: dict):
    """Append an entry to JSON (line-delimited) and CSV logs."""
    # JSON (line-delimited)
    try:
        with open(JSON_LOG, 'a') as jf:
            jf.write(json.dumps(entry) + '\n')
    except Exception as e:
        print('Failed to write JSON log:', e)

    # CSV
    try:
        write_header = not os.path.exists(CSV_LOG)
        with open(CSV_LOG, 'a', newline='') as cf:
            writer = csv.DictWriter(cf, fieldnames=list(entry.keys()))
            if write_header:
                writer.writeheader()
            writer.writerow(entry)
    except Exception as e:
        print('Failed to write CSV log:', e)

# ----------------- GUI -----------------

class ChecksumVerifierApp:
    def __init__(self, root):
        self.root = root
        root.title('Checksum Verifier')
        root.resizable(False, False)
        padding = 10

        frm = ttk.Frame(root, padding=padding)
        frm.grid(row=0, column=0, sticky='nsew')

        # File selection
        ttk.Label(frm, text='File:').grid(row=0, column=0, sticky='w')
        self.file_var = tk.StringVar()
        self.file_entry = ttk.Entry(frm, textvariable=self.file_var, width=60)
        self.file_entry.grid(row=0, column=1, columnspan=2, sticky='w')
        ttk.Button(frm, text='Browse...', command=self.browse_file).grid(row=0, column=3, padx=5)

        # Algorithm selection
        ttk.Label(frm, text='Algorithm:').grid(row=1, column=0, sticky='w', pady=(8,0))
        self.algo_var = tk.StringVar(value='sha256')
        algo_box = ttk.Combobox(frm, textvariable=self.algo_var, values=['md5', 'sha1', 'sha256'], width=12, state='readonly')
        algo_box.grid(row=1, column=1, sticky='w', pady=(8,0))

        # Compute button
        self.compute_btn = ttk.Button(frm, text='Compute Hash', command=self.compute_hash_action)
        self.compute_btn.grid(row=1, column=2, sticky='w', pady=(8,0))

        # Computed hash display
        ttk.Label(frm, text='Computed Hash:').grid(row=2, column=0, sticky='w', pady=(8,0))
        self.computed_var = tk.StringVar()
        self.computed_entry = ttk.Entry(frm, textvariable=self.computed_var, width=80)
        self.computed_entry.grid(row=2, column=1, columnspan=3, sticky='w', pady=(8,0))

        # Expected hash input
        ttk.Label(frm, text='Expected Hash (paste here to compare):').grid(row=3, column=0, sticky='w', pady=(8,0))
        self.expected_var = tk.StringVar()
        self.expected_entry = ttk.Entry(frm, textvariable=self.expected_var, width=80)
        self.expected_entry.grid(row=3, column=1, columnspan=3, sticky='w', pady=(8,0))

        # Compare button and result
        self.compare_btn = ttk.Button(frm, text='Compare', command=self.compare_action)
        self.compare_btn.grid(row=4, column=1, sticky='w', pady=(12,0))

        self.result_lbl = ttk.Label(frm, text='', font=('Segoe UI', 10, 'bold'))
        self.result_lbl.grid(row=4, column=2, columnspan=2, sticky='w', pady=(12,0))

        # Extra: Save expected as file hash button
        ttk.Button(frm, text='Save Computed to Clipboard', command=self.copy_computed).grid(row=5, column=1, sticky='w', pady=(12,0))
        ttk.Button(frm, text='Clear', command=self.clear_all).grid(row=5, column=2, sticky='w', pady=(12,0))

        # Footer / Help
        help_text = 'Select a file → choose algorithm → Compute Hash → Paste expected hash → Compare.'
        ttk.Label(frm, text=help_text, foreground='gray').grid(row=6, column=0, columnspan=4, sticky='w', pady=(12,0))

    def browse_file(self):
        path = filedialog.askopenfilename()
        if path:
            self.file_var.set(path)

    def compute_hash_action(self):
        path = self.file_var.get().strip()
        if not path or not os.path.exists(path):
            messagebox.showerror('Error', 'Please select a valid file')
            return
        algo = self.algo_var.get()
        try:
            self.root.config(cursor='watch')
            self.compute_btn.config(state='disabled')
            digest = compute_hash(path, algo)
            self.computed_var.set(digest)
            self.result_lbl.config(text='Hash computed', foreground='black')

            # Log
            entry = {
                'time': datetime.utcnow().isoformat() + 'Z',
                'file': path,
                'algorithm': algo,
                'computed_hash': digest
            }
            log_result(entry)
        except Exception as e:
            messagebox.showerror('Error', f'Failed to compute hash: {e}')
        finally:
            self.compute_btn.config(state='normal')
            self.root.config(cursor='')

    def compare_action(self):
        computed = self.computed_var.get().strip().lower()
        expected = self.expected_var.get().strip().lower()
        if not computed:
            messagebox.showwarning('Warning', 'Please compute the file hash first')
            return
        if not expected:
            messagebox.showwarning('Warning', 'Please paste the expected hash to compare')
            return

        match = (computed == expected)
        if match:
            self.result_lbl.config(text='MATCH ✓', foreground='green')
        else:
            self.result_lbl.config(text='MISMATCH ✗', foreground='red')

        # Log comparison
        entry = {
            'time': datetime.utcnow().isoformat() + 'Z',
            'file': self.file_var.get().strip(),
            'algorithm': self.algo_var.get(),
            'computed_hash': computed,
            'expected_hash': expected,
            'match': match
        }
        log_result(entry)

    def copy_computed(self):
        computed = self.computed_var.get().strip()
        if computed:
            self.root.clipboard_clear()
            self.root.clipboard_append(computed)
            messagebox.showinfo('Copied', 'Computed hash copied to clipboard')
        else:
            messagebox.showwarning('Warning', 'No computed hash to copy')

    def clear_all(self):
        self.file_var.set('')
        self.computed_var.set('')
        self.expected_var.set('')
        self.result_lbl.config(text='')


# ----------------- Run App -----------------

def main():
    root = tk.Tk()
    app = ChecksumVerifierApp(root)
    root.mainloop()


if __name__ == '__main__':
    main()
