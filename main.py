#!/usr/bin/env python3
import hashlib
import os
import json
import time
import random
import tkinter as tk
from tkinter import messagebox

STORE_FILE = os.path.expanduser("~/.password_trainer.json")
TIMES_DIR = os.path.expanduser("~/.password_trainer_times")

def hash_password(password, salt=None):
    if salt is None:
        salt = os.urandom(16).hex()
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100000).hex()
    return salt, h

def load_store():
    if os.path.exists(STORE_FILE):
        with open(STORE_FILE) as f:
            return json.load(f)
    return {}

def save_store(store):
    with open(STORE_FILE, "w") as f:
        json.dump(store, f, indent=2)

def get_times_file(label):
    os.makedirs(TIMES_DIR, exist_ok=True)
    safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in label)
    return os.path.join(TIMES_DIR, f"{safe_name}.csv")

def log_time(label, elapsed, correct):
    path = get_times_file(label)
    exists = os.path.exists(path)
    with open(path, "a") as f:
        if not exists:
            f.write("timestamp,elapsed,correct\n")
        f.write(f"{time.time()},{elapsed:.4f},{int(correct)}\n")


class PasswordTrainer:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Trainer")
        self.root.resizable(False, False)
        self.store = load_store()
        self.timer_start = None
        self.current_label = None
        self.session_correct = 0
        self.session_total = 0
        self._timer_id = None
        self.last_result_text = ""
        self.last_result_color = "#888"

        self.frame = tk.Frame(root, padx=20, pady=20)
        self.frame.pack()

        self.show_menu()

    def clear(self):
        if self._timer_id:
            self.root.after_cancel(self._timer_id)
            self._timer_id = None
        for w in self.frame.winfo_children():
            w.destroy()

    def pick_random_label(self):
        labels = list(self.store.keys())
        if len(labels) == 1:
            return labels[0]
        choices = [l for l in labels if l != self.current_label] or labels
        return random.choice(choices)

    # ---- MENU ----

    def show_menu(self):
        self.clear()
        self.session_correct = 0
        self.session_total = 0
        self.last_result_text = ""

        tk.Label(self.frame, text="Password Trainer", font=("Helvetica", 18, "bold")).pack(pady=(0, 5))
        tk.Label(self.frame, text=f"{len(self.store)} password(s) stored", font=("Helvetica", 11), fg="#666").pack(pady=(0, 15))

        btn_opts = dict(width=20, font=("Helvetica", 12), pady=5)
        tk.Button(self.frame, text="Add Password", command=self.show_add, **btn_opts).pack(pady=3)
        tk.Button(self.frame, text="Practice", command=self.show_practice, **btn_opts).pack(pady=3)
        tk.Button(self.frame, text="Stats", command=self.show_stats, **btn_opts).pack(pady=3)
        tk.Button(self.frame, text="Reset All", command=self.reset_all, **btn_opts).pack(pady=3)

    # ---- ADD PASSWORD ----

    def show_add(self):
        self.clear()
        tk.Label(self.frame, text="Add Password", font=("Helvetica", 16, "bold")).pack(pady=(0, 15))

        tk.Label(self.frame, text="Label (e.g. 'laptop', 'server'):", anchor="w").pack(fill="x")
        self.add_label_entry = tk.Entry(self.frame, font=("Helvetica", 12), width=30)
        self.add_label_entry.pack(pady=(0, 10))
        self.add_label_entry.focus_set()

        tk.Label(self.frame, text="Password:", anchor="w").pack(fill="x")
        self.add_pw_entry = tk.Entry(self.frame, show="•", font=("Helvetica", 12), width=30)
        self.add_pw_entry.pack(pady=(0, 10))

        tk.Label(self.frame, text="Confirm password:", anchor="w").pack(fill="x")
        self.add_pw2_entry = tk.Entry(self.frame, show="•", font=("Helvetica", 12), width=30)
        self.add_pw2_entry.pack(pady=(0, 10))

        self.add_msg = tk.Label(self.frame, text="", fg="red", font=("Helvetica", 10))
        self.add_msg.pack()

        btn_frame = tk.Frame(self.frame)
        btn_frame.pack(pady=10)
        tk.Button(btn_frame, text="Save", command=self.do_add, width=10, font=("Helvetica", 11)).pack(side="left", padx=5)
        tk.Button(btn_frame, text="Back", command=self.show_menu, width=10, font=("Helvetica", 11)).pack(side="left", padx=5)

        self.add_pw2_entry.bind("<Return>", lambda e: self.do_add())

    def do_add(self):
        label = self.add_label_entry.get().strip()
        pw = self.add_pw_entry.get()
        pw2 = self.add_pw2_entry.get()

        if not label:
            self.add_msg.config(text="Enter a label.")
            return
        if not pw:
            self.add_msg.config(text="Enter a password.")
            return
        if pw != pw2:
            self.add_msg.config(text="Passwords don't match.")
            self.add_pw_entry.delete(0, "end")
            self.add_pw2_entry.delete(0, "end")
            self.add_pw_entry.focus_set()
            return

        salt, h = hash_password(pw)
        self.store[label] = {"salt": salt, "hash": h, "streak": 0, "best_time": None}
        save_store(self.store)
        self.add_msg.config(text=f"Saved '{label}'!", fg="green")
        self.add_label_entry.delete(0, "end")
        self.add_pw_entry.delete(0, "end")
        self.add_pw2_entry.delete(0, "end")
        self.add_label_entry.focus_set()

    # ---- PRACTICE ----

    def show_practice(self):
        if not self.store:
            messagebox.showinfo("No passwords", "Add some passwords first.")
            return

        self.clear()
        self.current_label = self.pick_random_label()
        self.timer_start = None

        # Last result (persists from previous attempt)
        self.result_label = tk.Label(self.frame, text=self.last_result_text,
                                     font=("Helvetica", 12, "bold"), fg=self.last_result_color)
        self.result_label.pack(pady=(0, 5))

        session_text = f"Session: {self.session_correct}/{self.session_total}"
        self.session_label = tk.Label(self.frame, text=session_text, font=("Helvetica", 10), fg="#666")
        self.session_label.pack(pady=(0, 10))

        self.prompt_label = tk.Label(self.frame, text=f"Type password for: {self.current_label}",
                                     font=("Helvetica", 14))
        self.prompt_label.pack(pady=(0, 5))

        best = self.store[self.current_label].get("best_time")
        streak = self.store[self.current_label].get("streak", 0)
        info = f"Streak: {streak}"
        if best:
            info += f"  |  PR: {best:.2f}s"
        self.info_label = tk.Label(self.frame, text=info, font=("Helvetica", 10), fg="#888")
        self.info_label.pack(pady=(0, 10))

        self.pw_entry = tk.Entry(self.frame, show="•", font=("Helvetica", 14), width=30, justify="center")
        self.pw_entry.pack(pady=(0, 5))
        self.pw_entry.focus_set()
        self.pw_entry.bind("<KeyPress>", self.on_first_key)
        self.pw_entry.bind("<Return>", lambda e: self.check_password())

        self.timer_label = tk.Label(self.frame, text="", font=("Helvetica", 11, "bold"), fg="#888")
        self.timer_label.pack()

        self.hint_label = tk.Label(self.frame, text="Timer starts when you type", font=("Helvetica", 9), fg="#aaa")
        self.hint_label.pack()

        btn_frame = tk.Frame(self.frame)
        btn_frame.pack(pady=10)
        tk.Button(btn_frame, text="Submit", command=self.check_password, width=10, font=("Helvetica", 11)).pack(side="left", padx=5)
        tk.Button(btn_frame, text="Menu", command=self.show_menu, width=10, font=("Helvetica", 11)).pack(side="left", padx=5)

    def on_first_key(self, event):
        if event.keysym in ("Shift_L", "Shift_R", "Control_L", "Control_R",
                            "Alt_L", "Alt_R", "Meta_L", "Meta_R", "Caps_Lock",
                            "Tab", "Return", "Escape"):
            return
        if self.timer_start is None:
            self.timer_start = time.time()
            self.hint_label.config(text="")
            self.update_timer()

    def update_timer(self):
        if self.timer_start is not None:
            elapsed = time.time() - self.timer_start
            self.timer_label.config(text=f"{elapsed:.1f}s")
            self._timer_id = self.root.after(50, self.update_timer)

    def check_password(self):
        if self.timer_start is None:
            return

        if self._timer_id:
            self.root.after_cancel(self._timer_id)
            self._timer_id = None

        elapsed = time.time() - self.timer_start
        attempt = self.pw_entry.get()
        label = self.current_label

        salt = self.store[label]["salt"]
        _, h = hash_password(attempt, salt)
        self.session_total += 1

        if h == self.store[label]["hash"]:
            self.store[label]["streak"] = self.store[label].get("streak", 0) + 1
            self.session_correct += 1
            streak = self.store[label]["streak"]
            best = self.store[label].get("best_time")

            if best is None or elapsed < best:
                if best is not None:
                    self.last_result_text = f"✓ {label}: {elapsed:.2f}s — 🏆 NEW PR! (was {best:.2f}s) streak:{streak}"
                else:
                    self.last_result_text = f"✓ {label}: {elapsed:.2f}s — First time! streak:{streak}"
                self.last_result_color = "green"
                self.store[label]["best_time"] = round(elapsed, 4)
            else:
                diff = elapsed - best
                self.last_result_text = f"✓ {label}: {elapsed:.2f}s — +{diff:.2f}s off PR  streak:{streak}"
                self.last_result_color = "#2196F3"

            log_time(label, elapsed, True)
        else:
            self.store[label]["streak"] = 0
            self.last_result_text = f"✗ {label}: Wrong ({elapsed:.2f}s)"
            self.last_result_color = "red"
            log_time(label, elapsed, False)

        save_store(self.store)
        self.show_practice()

    # ---- STATS ----

    def show_stats(self):
        if not self.store:
            messagebox.showinfo("No passwords", "Add some passwords first.")
            return

        self.clear()
        tk.Label(self.frame, text="Stats", font=("Helvetica", 16, "bold")).pack(pady=(0, 15))

        for label in self.store:
            entry = self.store[label]
            streak = entry.get("streak", 0)
            best = entry.get("best_time")

            total_attempts = 0
            correct_attempts = 0
            times_file = get_times_file(label)
            if os.path.exists(times_file):
                with open(times_file) as f:
                    lines = f.readlines()[1:]
                    total_attempts = len(lines)
                    correct_attempts = sum(1 for l in lines if l.strip().endswith(",1"))

            row = tk.Frame(self.frame)
            row.pack(fill="x", pady=5)

            tk.Label(row, text=label, font=("Helvetica", 12, "bold"), anchor="w", width=15).pack(side="left")

            details = f"Streak: {streak}"
            if best:
                details += f"  |  PR: {best:.2f}s"
            if total_attempts:
                pct = (correct_attempts / total_attempts) * 100
                details += f"  |  {correct_attempts}/{total_attempts} ({pct:.0f}%)"

            tk.Label(row, text=details, font=("Helvetica", 10), fg="#555", anchor="w").pack(side="left", padx=10)

        tk.Label(self.frame, text=f"\nTime logs: {TIMES_DIR}/", font=("Helvetica", 9), fg="#aaa").pack(pady=(10, 0))
        tk.Button(self.frame, text="Back", command=self.show_menu, width=10, font=("Helvetica", 11)).pack(pady=15)

    # ---- RESET ----

    def reset_all(self):
        if not messagebox.askyesno("Reset", "Delete all stored passwords and times?"):
            return
        if os.path.exists(STORE_FILE):
            os.remove(STORE_FILE)
        if os.path.exists(TIMES_DIR):
            import shutil
            shutil.rmtree(TIMES_DIR)
        self.store.clear()
        self.show_menu()


if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordTrainer(root)
    root.mainloop()