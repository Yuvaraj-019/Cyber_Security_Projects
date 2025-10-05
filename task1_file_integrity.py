# ============================================================
# File Integrity Checker - Final Version (Menu + Log File)
# Author: Atreus
# Description:
#   Monitors files for changes using SHA-256 hashes.
#   Provides a menu for scanning, viewing, resetting, and logs.
# ============================================================

import hashlib
import os
import json
from pathlib import Path
from datetime import datetime

HASH_DB = "hashes.json"
LOG_FILE = "scan_report.txt"

# --------------------- Core Functions ---------------------

def sha256_file(path):
    """Compute SHA-256 hash of a given file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def load_db():
    """Load existing hash database (JSON file)."""
    if not os.path.exists(HASH_DB):
        return {}
    with open(HASH_DB, "r") as f:
        return json.load(f)

def save_db(db):
    """Save hash database back to file."""
    with open(HASH_DB, "w") as f:
        json.dump(db, f, indent=2)

def log_scan(report, folder):
    """Save the scan report summary into a text log file."""
    with open(LOG_FILE, "a") as f:
        f.write("\n" + "=" * 70 + "\n")
        f.write(f"[SCAN REPORT] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Scanned Folder: {folder}\n")
        f.write(f"Modified Files: {len(report['modified'])}\n")
        f.write(f"New Files: {len(report['new'])}\n")
        f.write(f"Unchanged Files: {len(report['unchanged'])}\n")
        f.write(f"Missing Files: {len(report['missing'])}\n")

        if report["modified"]:
            f.write("\nModified Files:\n")
            for item in report["modified"]:
                f.write(f"  - {item}\n")

        if report["new"]:
            f.write("\nNew Files:\n")
            for item in report["new"]:
                f.write(f"  - {item}\n")

        if report["missing"]:
            f.write("\nMissing Files:\n")
            for item in report["missing"]:
                f.write(f"  - {item}\n")

        f.write("=" * 70 + "\n")

def scan_folder(folder):
    """Scan folder and detect changes compared to last known state."""
    db = load_db()
    folder = Path(folder)
    report = {"modified": [], "new": [], "unchanged": [], "missing": []}
    tracked = set(db.keys())

    for p in folder.rglob("*"):
        if p.is_file():
            rel = str(p.relative_to(folder))
            current_hash = sha256_file(p)
            if rel not in db:
                report["new"].append(rel)
                db[rel] = current_hash
            elif db[rel] != current_hash:
                report["modified"].append(rel)
                db[rel] = current_hash
            else:
                report["unchanged"].append(rel)
            if rel in tracked:
                tracked.remove(rel)

    for missing in tracked:
        report["missing"].append(missing)
        db.pop(missing, None)

    save_db(db)
    log_scan(report, folder)
    return report

# --------------------- Utility Functions ---------------------

def view_hash_database():
    """Display all stored file hashes in a safe, professional format."""
    db = load_db()
    if not db:
        print("\n[!] Hash database is empty.")
        return

    print("\nTracked Files (Partial Hash View):")
    print("-" * 70)
    for file, h in db.items():
        print(f"{file:40}  |  Hash: {h[:8]}... (hidden for security)")
    print("-" * 70)
    print(f"Total files tracked: {len(db)}")
    print("\n[ℹ️] Only first 8 characters of each hash are shown for privacy.")


def view_scan_history():
    """Display the scan history log."""
    if not os.path.exists(LOG_FILE):
        print("\n[!] No scan history found.")
        return
    print("\n📜 Scan History:")
    print("-" * 70)
    with open(LOG_FILE, "r") as f:
        print(f.read())
    print("-" * 70)

def reset_database():
    """Clear all saved hashes and logs (use carefully)."""
    if os.path.exists(HASH_DB):
        os.remove(HASH_DB)
        print("\n[✔] Hash database reset successfully.")
    if os.path.exists(LOG_FILE):
        os.remove(LOG_FILE)
        print("[✔] Scan history log cleared.")
    else:
        print("\n[!] Nothing to reset.")

# --------------------- Menu System ---------------------

def main_menu():
    while True:
        print("\n" + "=" * 60)
        print(" 🔒 FILE INTEGRITY CHECKER (SHA-256) ")
        print("=" * 60)
        print("1. Scan a Folder for Changes")
        print("2. View Stored File Hashes")
        print("3. View Scan History Log")
        print("4. Reset Hash Database & Logs")
        print("5. Exit")
        print("-" * 60)

        choice = input("Enter your choice (1-5): ").strip()

        if choice == "1":
            folder = input("\nEnter folder path to scan: ").strip()
            if not os.path.exists(folder):
                print("[!] Folder not found. Try again.")
                continue
            print("\n[⏳] Scanning in progress...")
            report = scan_folder(folder)
            print("\n[📊] Scan Report:")
            for k, v in report.items():
                print(f"  {k.capitalize():10}: {len(v)} files")
            if report["modified"]:
                print("\nModified Files:")
                for f in report["modified"]:
                    print("  -", f)
            print("\n[✔] Report saved to 'scan_report.txt'")
        elif choice == "2":
            view_hash_database()
        elif choice == "3":
            view_scan_history()
        elif choice == "4":
            confirm = input("⚠ Are you sure you want to reset everything? (y/n): ")
            if confirm.lower() == "y":
                reset_database()
        elif choice == "5":
            print("\nGoodbye 👋 Stay Secure!")
            break
        else:
            print("\n[!] Invalid choice. Please select 1–5.")

# --------------------- Entry Point ---------------------

if __name__ == "__main__":
    main_menu()
