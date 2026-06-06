"""
Test 8: WIPER Ransomware (Destroy Without Encryption)
يحاكي wiper يحذف ملفات بدون تشفير — فقط حذف جماعي سريع
بعض الرانسوموير ما يشفّر — يحذف وبس (مثل NotPetya)
🎯 الطبقة المستهدفة: L2c (Mass Delete) بدون L2b (لأن ما فيه ransom extensions)
"""
import os, time, shutil

TEST_DIRS = [
    os.path.join(os.path.expanduser("~"), "Documents", "_ransomshield_test8_wiper"),
    os.path.join(os.path.expanduser("~"), "Desktop", "_ransomshield_test8_wiper"),
    os.path.join(os.path.expanduser("~"), "Pictures", "_ransomshield_test8_wiper"),
]

for d in TEST_DIRS:
    os.makedirs(d, exist_ok=True)

print("=" * 60)
print("[TEST 8] WIPER RANSOMWARE — Mass Destruction (No Encryption)")
print(f"  Targets: {len(TEST_DIRS)} directories")
print(f"  Strategy: Pure deletion, no encryption, maximum speed")
print("=" * 60)

# Phase 1: إنشاء ملفات كثيرة
print("\n[Phase 1] Creating 90 target files (30 per directory)...")
all_files = []
exts = [".docx", ".xlsx", ".pdf", ".jpg", ".png", ".txt",
        ".pptx", ".csv", ".mp3", ".zip"]
for d in TEST_DIRS:
    folder = os.path.basename(os.path.dirname(d))
    for i in range(30):
        ext = exts[i % len(exts)]
        fp = os.path.join(d, f"data_{folder}_{i}{ext}")
        with open(fp, "w") as f:
            f.write(f"Critical data file {i} in {folder} " * 300)
        all_files.append(fp)
    print(f"  [{folder}] 30 files created")

print(f"\n  Total: {len(all_files)} files ready")
print(f"\n[Phase 2] Starting WIPE in 3 seconds...")
time.sleep(3)

# Phase 2: حذف سريع جداً — بدون تشفير
print("[Phase 2] WIPING — Maximum speed deletion!")
start = time.time()
deleted = 0
for fp in all_files:
    try:
        os.remove(fp)
        deleted += 1
        if deleted % 15 == 0:
            elapsed = time.time() - start
            rate = deleted / max(elapsed, 0.01)
            print(f"  [WIPE] {deleted}/{len(all_files)} deleted "
                  f"({rate:.0f} files/sec)")
    except Exception:
        pass
    time.sleep(0.01)  # حذف سريع جداً

elapsed = time.time() - start
print(f"\n[TEST 8] ✅ Wipe complete!")
print(f"  Deleted: {deleted} files in {elapsed:.1f} seconds")
print(f"  Rate: {deleted / max(elapsed, 0.01):.0f} files/second")
print("\n[TEST 8] Cleaning up in 3 seconds...")
time.sleep(3)
for d in TEST_DIRS:
    shutil.rmtree(d, ignore_errors=True)
print("[TEST 8] Cleaned.")
