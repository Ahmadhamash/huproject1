"""
Test 7: MULTI-STAGE Ransomware (Staged Attack)
يحاكي رانسوموير متقدم بمراحل:
  Stage 1: Reconnaissance — يستكشف الملفات بدون تعديل
  Stage 2: Staging — ينسخ أدوات من temp لمجلدات المستخدم (temp→user bridge)
  Stage 3: Encryption — يبدأ التشفير الفعلي
  Stage 4: Ransom Note — يضع ملف فدية في كل مجلد

هذا أصعب نوع للكشف لأن كل مرحلة لوحدها تبدو طبيعية
🎯 الطبقات المستهدفة: temp_to_user_bridge + L2a + L2b + L3
"""
import os, time, shutil, tempfile

BASE = os.path.expanduser("~")
TEST_DIR = os.path.join(BASE, "Documents", "_ransomshield_test7_staged")
TEMP_STAGE = os.path.join(tempfile.gettempdir(), "_rs_test7_staging")

os.makedirs(TEST_DIR, exist_ok=True)
os.makedirs(TEMP_STAGE, exist_ok=True)

SUBDIRS = ["Contracts", "Invoices", "Reports"]
for sd in SUBDIRS:
    os.makedirs(os.path.join(TEST_DIR, sd), exist_ok=True)

print("=" * 60)
print("[TEST 7] MULTI-STAGE RANSOMWARE — Staged Attack")
print(f"  User data : {TEST_DIR}")
print(f"  Temp stage: {TEMP_STAGE}")
print("=" * 60)

# ── Stage 0: Create target files ────────────────────────
print("\n[Stage 0] Creating target files...")
target_files = []
for sd in SUBDIRS:
    for i in range(6):
        exts = [".docx", ".xlsx", ".pdf", ".csv", ".pptx", ".txt"]
        ext = exts[i % len(exts)]
        fp = os.path.join(TEST_DIR, sd, f"{sd.lower()}_{i}{ext}")
        with open(fp, "w") as f:
            f.write(f"Confidential {sd} document #{i} " * 200)
        target_files.append(fp)
print(f"  Created {len(target_files)} files across {len(SUBDIRS)} folders")

# ── Stage 1: Reconnaissance (5 seconds) ────────────────
print(f"\n[Stage 1] RECONNAISSANCE — Scanning files (no modifications)...")
time.sleep(2)
file_inventory = []
for sd in SUBDIRS:
    d = os.path.join(TEST_DIR, sd)
    for fname in os.listdir(d):
        fp = os.path.join(d, fname)
        size = os.path.getsize(fp)
        file_inventory.append((fp, size))
        print(f"  [SCAN] {sd}/{fname} ({size} bytes)")
    time.sleep(1)

print(f"  Inventory: {len(file_inventory)} files found")

# ── Stage 2: Staging in TEMP (temp→user bridge) ────────
print(f"\n[Stage 2] STAGING — Creating tools in TEMP directory...")
time.sleep(2)

# إنشاء "أدوات" في مجلد temp
staging_files = []
for i in range(5):
    fp = os.path.join(TEMP_STAGE, f"module_{i}.dat")
    with open(fp, "w") as f:
        f.write(f"STAGED_ENCRYPTION_MODULE_{i}" * 100)
    staging_files.append(fp)
    print(f"  [STAGE] Created: module_{i}.dat in TEMP")
    time.sleep(0.5)

# نسخ من temp لمجلد user (هذا الـ bridge)
print(f"\n[Stage 2b] Copying staging files to user directory...")
for sf in staging_files:
    dest = os.path.join(TEST_DIR, os.path.basename(sf))
    shutil.copy2(sf, dest)
    print(f"  [BRIDGE] TEMP → Documents: {os.path.basename(sf)}")
    time.sleep(0.3)

# ── Stage 3: Encryption ───────────────────────────────
print(f"\n[Stage 3] ENCRYPTION — Starting file encryption...")
time.sleep(2)

encrypted = 0
for fp, size in file_inventory:
    basename = os.path.splitext(os.path.basename(fp))[0]
    dirname = os.path.dirname(fp)

    # حذف الأصلي
    os.remove(fp)

    # إنشاء ملف "مشفر"
    enc = os.path.join(dirname, f"{basename}.encrypted")
    with open(enc, "w") as f:
        f.write("STAGE3_ENCRYPTED_CONTENT_" + "X" * 500)

    encrypted += 1
    sd = os.path.basename(dirname)
    print(f"  [ENCRYPT {encrypted:2d}] {sd}/{basename} -> .encrypted")
    time.sleep(0.15)

# ── Stage 4: Ransom Notes ─────────────────────────────
print(f"\n[Stage 4] RANSOM NOTES — Dropping ransom notes...")
time.sleep(1)
for sd in SUBDIRS:
    note_path = os.path.join(TEST_DIR, sd, "HOW_TO_DECRYPT.txt")
    with open(note_path, "w") as f:
        f.write("=== THIS IS A TEST — NOT REAL RANSOMWARE ===\n" * 5)
    print(f"  [NOTE] {sd}/HOW_TO_DECRYPT.txt")
    time.sleep(0.3)

# Main ransom note
main_note = os.path.join(TEST_DIR, "README_RESTORE_FILES.txt")
with open(main_note, "w") as f:
    f.write("=== TEST SIMULATION ONLY ===\n" * 10)
print(f"  [NOTE] README_RESTORE_FILES.txt")

print(f"\n[TEST 7] ✅ Attack complete!")
print(f"  Files encrypted: {encrypted}")
print(f"  Ransom notes: {len(SUBDIRS) + 1}")
print(f"  Temp bridge: YES (5 files)")
print("\n[TEST 7] Cleaning up in 5 seconds...")
time.sleep(5)
shutil.rmtree(TEST_DIR, ignore_errors=True)
shutil.rmtree(TEMP_STAGE, ignore_errors=True)
print("[TEST 7] Cleaned.")
