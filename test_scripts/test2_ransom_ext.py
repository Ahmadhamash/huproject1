"""
Test 2: Ransom Extension Simulation
ينشئ ملفات بامتدادات رانسوموير معروفة (.encrypted, .wcry, .locky)
يعمل فقط داخل مجلد مؤقت — آمن تماماً
"""
import os, time, shutil

TEST_DIR = os.path.join(os.path.expanduser("~"), "Documents", "_ransomshield_test2")
os.makedirs(TEST_DIR, exist_ok=True)

RANSOM_EXTS = [".encrypted", ".wcry", ".locky", ".cerber", ".locked", 
               ".crypted", ".dharma", ".ryuk", ".conti", ".lockbit"]

print(f"[TEST 2] Ransom Extensions — Working in: {TEST_DIR}")
print("[TEST 2] Creating files with known ransomware extensions...")

for i, ext in enumerate(RANSOM_EXTS):
    # إنشاء ملف أصلي
    orig = os.path.join(TEST_DIR, f"photo_{i}.jpg")
    with open(orig, "w") as f:
        f.write(f"Fake image data {i} " * 100)
    
    time.sleep(0.05)
    os.remove(orig)
    
    # إنشاء ملف بامتداد رانسوموير
    ransom_file = os.path.join(TEST_DIR, f"photo_{i}{ext}")
    with open(ransom_file, "w") as f:
        f.write("SIMULATED_RANSOM")
    
    print(f"  [*] photo_{i}.jpg -> photo_{i}{ext}")
    time.sleep(0.15)

print(f"\n[TEST 2] Done! Cleaning up...")
time.sleep(3)
shutil.rmtree(TEST_DIR, ignore_errors=True)
print("[TEST 2] Cleaned.")
