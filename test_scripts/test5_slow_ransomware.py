"""
Test 5 (v2): SLOW Ransomware — Low & Slow
يحاكي رانسوموير بطيء: يشفّر ملف كل 5 ثواني
يختبر:
  - L2b: تراكم ransom extensions (بعد 3 ملفات)
  - L2f: Slow Ransomware detection (بعد 10 ثواني)
  - preserve: هل الإشارات تتراكم عبر window resets

المدة: ~90 ثانية (15 ملفات × 5 ثواني)
"""
import os, time, shutil

TEST_DIR = os.path.join(os.path.expanduser("~"), "Documents", "_ransomshield_test5_slow")
os.makedirs(TEST_DIR, exist_ok=True)

EXTENSIONS = [".docx", ".xlsx", ".pdf", ".jpg", ".txt", ".pptx", ".csv"]

print("=" * 60)
print("[TEST 5] SLOW RANSOMWARE v2 — Low & Slow")
print(f"  Working in: {TEST_DIR}")
print(f"  Strategy: 1 file every ~5 seconds")
print(f"  Expected detection: L2f (SLOW RANSOM) after ~15-25 seconds")
print("=" * 60)

# Phase 1: إنشاء الملفات
print("\n[Phase 1] Creating 15 target files...")
files = []
for i in range(15):
    ext = EXTENSIONS[i % len(EXTENSIONS)]
    fp = os.path.join(TEST_DIR, f"report_{i}{ext}")
    with open(fp, "w") as f:
        f.write(f"Quarterly report data Q{i % 4 + 1} " * 200)
    files.append(fp)
    print(f"  Created: report_{i}{ext}")

print(f"\n[Phase 2] Waiting 3 seconds before starting...\n")
time.sleep(3)

# Phase 2: تشفير بطيء — .encrypted موجود بقائمة RANSOM_EXTENSIONS
print("[Phase 2] Slow encryption (1 file every 5 seconds)...")
for i, fp in enumerate(files):
    basename = os.path.splitext(os.path.basename(fp))[0]
    orig_ext = os.path.splitext(fp)[1]

    # حذف الأصلي
    os.remove(fp)
    # إنشاء بامتداد ransomware
    enc_path = os.path.join(TEST_DIR, f"{basename}.encrypted")
    with open(enc_path, "w") as f:
        f.write("SLOW_ENCRYPTED_DATA_" + "X" * 500)

    elapsed = (i + 1) * 5
    print(f"  [{i+1:2d}/15] {basename}{orig_ext} -> {basename}.encrypted  "
          f"(~{elapsed}s elapsed)")

    if i < len(files) - 1:
        time.sleep(5)

print(f"\n[TEST 5] Done! {len(files)} files encrypted slowly")
print("[TEST 5] Cleaning up in 5 seconds...")
time.sleep(5)
shutil.rmtree(TEST_DIR, ignore_errors=True)
print("[TEST 5] Cleaned.")
