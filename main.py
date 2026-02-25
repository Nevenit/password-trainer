#!/usr/bin/env python3
import hashlib
import getpass
import random
import os
import json
import time

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

def add_passwords(store):
    print("\n--- Add Passwords ---")
    print("Give each password a label (e.g. 'laptop', 'server').")
    print("Enter a blank label when done.\n")

    while True:
        label = input("Label: ").strip()
        if not label:
            break
        pw = getpass.getpass(f"Password for '{label}': ")
        pw2 = getpass.getpass(f"Confirm '{label}': ")
        if pw != pw2:
            print("Passwords don't match, try again.\n")
            continue
        salt, h = hash_password(pw)
        store[label] = {"salt": salt, "hash": h, "streak": 0, "best_time": None}
        print(f"Saved '{label}'.\n")

    save_store(store)
    return store

def practice(store):
    if not store:
        print("No passwords stored. Add some first.\n")
        return

    labels = list(store.keys())
    correct = 0
    total = 0

    print("\n--- Practice Mode ---")
    print(f"Passwords: {', '.join(labels)}")
    for label in labels:
        best = store[label].get("best_time")
        if best:
            print(f"  {label}: PR {best:.2f}s")
    print("Ctrl+C to stop.\n")

    try:
        while True:
            label = random.choice(labels)

            start = time.time()
            attempt = getpass.getpass(f"Type password for '{label}': ")
            elapsed = time.time() - start

            salt = store[label]["salt"]
            _, h = hash_password(attempt, salt)
            total += 1

            if h == store[label]["hash"]:
                store[label]["streak"] += 1
                correct += 1
                streak = store[label]["streak"]
                best = store[label].get("best_time")

                if best is None or elapsed < best:
                    if best is not None:
                        print(f"  \u2713 {elapsed:.2f}s \u2014 \U0001f3c6 NEW PR! (was {best:.2f}s) (streak: {streak})\n")
                    else:
                        print(f"  \u2713 {elapsed:.2f}s \u2014 First time recorded! (streak: {streak})\n")
                    store[label]["best_time"] = round(elapsed, 4)
                else:
                    diff = elapsed - best
                    print(f"  \u2713 {elapsed:.2f}s \u2014 +{diff:.2f}s off PR (streak: {streak})\n")

                log_time(label, elapsed, True)
            else:
                store[label]["streak"] = 0
                print(f"  \u2717 Wrong. ({elapsed:.2f}s)\n")
                log_time(label, elapsed, False)

            save_store(store)

    except KeyboardInterrupt:
        print(f"\n\nSession: {correct}/{total}")
        for label in labels:
            best = store[label].get("best_time")
            best_str = f", PR {best:.2f}s" if best else ""
            print(f"  {label}: streak {store[label]['streak']}{best_str}")
        print()

def reset_store(store):
    confirm = input("Delete all stored passwords and times? (yes/no): ").strip().lower()
    if confirm == "yes":
        if os.path.exists(STORE_FILE):
            os.remove(STORE_FILE)
        if os.path.exists(TIMES_DIR):
            import shutil
            shutil.rmtree(TIMES_DIR)
        store.clear()
        print("Cleared.\n")
    return store

def main():
    store = load_store()

    while True:
        print("=== Password Trainer ===")
        print(f"  {len(store)} password(s) stored")
        if store:
            print(f"  Times logged to: {TIMES_DIR}/")
        print()
        print("  1. Add passwords")
        print("  2. Practice")
        print("  3. Reset")
        print("  4. Quit")
        print()

        choice = input("> ").strip()

        if choice == "1":
            store = add_passwords(store)
        elif choice == "2":
            practice(store)
        elif choice == "3":
            store = reset_store(store)
        elif choice == "4":
            break
        else:
            print()

if __name__ == "__main__":
    main()