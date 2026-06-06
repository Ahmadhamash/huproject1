"""
Test 10: DOUBLE EXTORTION Ransomware
يحاكي رانسوموير يعمل نسخة من الملفات لمجلد temp (exfiltration) 
ثم يشفّر الأصلية — يحاكي سرقة البيانات قبل التشفير
🎯 الطبقات: temp_to_user_bridge + L2a + L2b + unique_dirs_touched
"""
import os, time, shutil, tempfile

BASE = os.path.expanduser("~")
TEST_DIR = os.path.join(BASE, "Documents", "_ransomshield_test10_double")
EXFIL_DIR = os.path.join(tempfile.gettempdir(), "_rs_test10_exfil")

os.makedirs(TEST_DIR, exist_ok=True)
os.makedirs(EXFIL_DIR, exist_ok=True)

print("=" * 60)
print("[TEST 10] DOUBLE EXTORTION RANSOMWARE")
print(f"  User data  : {TEST_DIR}")
print(f"  Exfil (temp): {EXFIL_DIR}")
print(f"  Strategy: Copy files to temp (exfiltrate) then encrypt originals")
print("=" * 60)

# Phase 1: إنشاء ملفات
print("\n[Phase 1] Creating 15 high-value files...")
files = []
EXTS = [".docx", ".xlsx", ".pdf", ".csv", ".pptx"]
for i in range(15):
    ext = EXTS[i % len(EXTS)]
    fp = os.path.join(TEST_DIR, f"confidential_{i}{ext}")
    with open(fp, "w") as f:
        f.write(f"CONFIDENTIAL: Trade secret #{i}. " * 300)
    files.append(fp)
    print(f"  Created: confidential_{i}{ext}")

# Phase 2: Exfiltration (نسخ لـ temp)
print(f"\n[Phase 2] EXFILTRATION — Copying files to temp (simulated upload)...")
time.sleep(2)
for i, fp in enumerate(files):
    fname = os.path.basename(fp)
    dest = os.path.join(EXFIL_DIR, fname)
    shutil.copy2(fp, dest)
    print(f"  [EXFIL {i+1:2d}] {fname} -> TEMP")
    time.sleep(0.3)

# Phase 3: Encryption
print(f"\n[Phase 3] ENCRYPTION — Encrypting originals...")
time.sleep(2)
for i, fp in enumerate(files):
    basename = os.path.splitext(os.path.basename(fp))[0]
    os.remove(fp)
    enc = os.path.join(TEST_DIR, f"{basename}.crypted")
    with open(enc, "w") as f:
        f.write("DOUBLE_EXTORTION_ENCRYPTED")
    print(f"  [ENCRYPT {i+1:2d}] {basename} -> .crypted")
    time.sleep(0.1)

# Phase 4: Cleanup exfil
print(f"\n[Phase 4] Dropping ransom note with proof of exfiltration...")
note = os.path.join(TEST_DIR, "YOUR_FILES_ARE_STOLEN.txt")
with open(note, "w") as f:
    f.write("=== TEST SIMULATION ONLY ===\n")
    f.write(f"We have copies of {len(files)} files.\n")
    f.write("Pay or we publish them.\n")
    f.write("=== THIS IS A TEST ===\n")

print(f"\n[TEST 10] ✅ Double extortion complete!")
print(f"  Exfiltrated: {len(files)} files")
print(f"  Encrypted: {len(files)} files")
print("\n[TEST 10] Cleaning up in 5 seconds...")
time.sleep(5)
shutil.rmtree(TEST_DIR, ignore_errors=True)
shutil.rmtree(EXFIL_DIR, ignore_errors=True)
print("[TEST 10] Cleaned.")
