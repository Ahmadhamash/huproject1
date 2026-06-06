"""
Test 9 (v2): Random Extension Ransomware
يحاكي رانسوموير يستخدم امتدادات عشوائية مش بالقائمة المعروفة
يختبر:
  - L2g: Novel/Anomalous Extension detection
  - L2f: Slow ransomware with novel extensions

المدة: ~25 ثانية
"""
import os, time, shutil, random, string

TEST_DIR = os.path.join(os.path.expanduser("~"), "Documents", "_ransomshield_test9_random")
os.makedirs(TEST_DIR, exist_ok=True)

print("=" * 60)
print("[TEST 9] RANDOM EXTENSION RANSOMWARE")
print(f"  Working in: {TEST_DIR}")
print(f"  Strategy: Uses random unknown extension (.x7k3m)")
print(f"  Expected detection: L2g (NOVEL EXT) after ~3-5 files")
print("=" * 60)

# Phase 1: إنشاء ملفات عادية
print("\n[Phase 1] Creating 10 normal files...")
files = []
exts = [".docx", ".xlsx", ".pdf", ".jpg", ".txt"]
for i in range(10):
    ext = exts[i % len(exts)]
    fp = os.path.join(TEST_DIR, f"data_{i}{ext}")
    with open(fp, "w") as f:
        f.write(f"Normal document content {i} " * 100)
    files.append(fp)
    print(f"  Created: data_{i}{ext}")

# Generate a random extension (NOT in COMMON_EXTENSIONS or RANSOM_EXTENSIONS)
random_ext = "." + "".join(random.choices(string.ascii_lowercase + string.digits, k=5))
print(f"\n  Random extension: {random_ext}")

time.sleep(3)

# Phase 2: تشفير بالامتداد العشوائي
print(f"\n[Phase 2] Encrypting with random extension: {random_ext}")
for i, fp in enumerate(files):
    basename = os.path.splitext(os.path.basename(fp))[0]
    
    # حذف الأصلي
    os.remove(fp)
    # إنشاء بالامتداد العشوائي
    enc_path = os.path.join(TEST_DIR, f"{basename}{random_ext}")
    with open(enc_path, "w") as f:
        f.write("ENCRYPTED_WITH_RANDOM_EXTENSION_" + "X" * 500)
    
    print(f"  [{i+1:2d}/10] data_{i} -> {basename}{random_ext}")
    time.sleep(1)

print(f"\n[TEST 9] Done! 10 files encrypted with {random_ext}")
print("[TEST 9] Cleaning up in 5 seconds...")
time.sleep(5)
shutil.rmtree(TEST_DIR, ignore_errors=True)
print("[TEST 9] Cleaned.")
