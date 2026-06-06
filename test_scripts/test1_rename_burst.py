"""
Test 1: Rename Burst Simulation
يحاكي سلوك إعادة تسمية الملفات بامتدادات مشبوهة
يعمل فقط داخل مجلد مؤقت خاص به — آمن تماماً
"""
import os, time, tempfile, shutil

TEST_DIR = os.path.join(os.path.expanduser("~"), "Documents", "_ransomshield_test1")
os.makedirs(TEST_DIR, exist_ok=True)

print(f"[TEST 1] Rename Burst — Working in: {TEST_DIR}")
print("[TEST 1] Creating original files then 'renaming' them...")

for i in range(20):
    # إنشاء ملف أصلي
    orig = os.path.join(TEST_DIR, f"report_{i}.docx")
    with open(orig, "w") as f:
        f.write(f"Test document {i} " * 50)
    
    time.sleep(0.05)
    
    # حذف الأصلي وإنشاء نسخة بامتداد مشبوه (محاكاة التشفير)
    os.remove(orig)
    encrypted = os.path.join(TEST_DIR, f"report_{i}.locked")
    with open(encrypted, "w") as f:
        f.write("SIMULATED_ENCRYPTED_CONTENT")
    
    print(f"  [*] report_{i}.docx -> report_{i}.locked")
    time.sleep(0.1)

print(f"\n[TEST 1] Done! Cleaning up...")
time.sleep(3)
shutil.rmtree(TEST_DIR, ignore_errors=True)
print("[TEST 1] Cleaned.")
