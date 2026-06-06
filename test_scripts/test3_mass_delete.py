"""
Test 3: Mass Delete in User Data Simulation
يحذف ملفات بكميات كبيرة وبسرعة عالية في مجلد Documents
يعمل فقط داخل مجلد مؤقت خاص — آمن تماماً
"""
import os, time, shutil

TEST_DIR = os.path.join(os.path.expanduser("~"), "Documents", "_ransomshield_test3")
os.makedirs(TEST_DIR, exist_ok=True)

print(f"[TEST 3] Mass Delete — Working in: {TEST_DIR}")

# أولاً: إنشاء 50 ملف
print("[TEST 3] Phase 1: Creating 50 files...")
files = []
for i in range(50):
    fp = os.path.join(TEST_DIR, f"important_data_{i}.xlsx")
    with open(fp, "w") as f:
        f.write(f"Critical spreadsheet data row {i} " * 200)
    files.append(fp)

print("[TEST 3] Phase 2: Rapid mass deletion (simulating ransomware)...")
time.sleep(1)

# ثانياً: حذف سريع جداً (محاكاة سلوك الرانسوموير)
for i, fp in enumerate(files):
    os.remove(fp)
    if i % 10 == 0:
        print(f"  [*] Deleted {i+1}/50 files...")
    time.sleep(0.02)  # حذف سريع

print(f"\n[TEST 3] Done! Cleaning up...")
time.sleep(3)
shutil.rmtree(TEST_DIR, ignore_errors=True)
print("[TEST 3] Cleaned.")
