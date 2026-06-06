"""
Test 4: Full Attack Simulation (All Patterns Combined)
يجمع كل الأنماط: إنشاء + حذف + امتدادات مشبوهة + مجلدات متعددة
أقوى اختبار — يفترض يطلق كل طبقات الكشف
يعمل فقط داخل مجلدات مؤقتة — آمن تماماً
"""
import os, time, shutil

BASE = os.path.expanduser("~")
TEST_DIRS = [
    os.path.join(BASE, "Documents", "_ransomshield_test4"),
    os.path.join(BASE, "Desktop", "_ransomshield_test4"),
    os.path.join(BASE, "Pictures", "_ransomshield_test4"),
]

for d in TEST_DIRS:
    os.makedirs(d, exist_ok=True)

print("[TEST 4] FULL ATTACK SIMULATION")
print(f"[TEST 4] Working across {len(TEST_DIRS)} directories\n")

EXTENSIONS = [".docx", ".xlsx", ".pdf", ".jpg", ".png", ".txt", ".pptx"]
RANSOM_EXT = [".encrypted", ".locked", ".wcry", ".dharma", ".conti"]

file_count = 0

for d in TEST_DIRS:
    folder_name = os.path.basename(os.path.dirname(d))
    print(f"  [{folder_name}] Creating and 'encrypting' files...")
    
    for i in range(15):
        ext = EXTENSIONS[i % len(EXTENSIONS)]
        rext = RANSOM_EXT[i % len(RANSOM_EXT)]
        
        # إنشاء الملف الأصلي
        orig = os.path.join(d, f"file_{i}{ext}")
        with open(orig, "w") as f:
            f.write(f"Important data in {folder_name} #{i} " * 100)
        
        time.sleep(0.03)
        
        # حذف الأصلي
        os.remove(orig)
        
        # إنشاء النسخة "المشفرة"
        enc = os.path.join(d, f"file_{i}{rext}")
        with open(enc, "w") as f:
            f.write("ENCRYPTED_BY_TEST_RANSOMWARE_SIMULATOR")
        
        file_count += 1
        time.sleep(0.05)
    
    # إنشاء ransom note (ملف الفدية)
    note = os.path.join(d, "README_DECRYPT.txt")
    with open(note, "w") as f:
        f.write("THIS IS A TEST - NOT REAL RANSOMWARE\n" * 10)
    
    print(f"  [{folder_name}] Done — 15 files 'encrypted'")

print(f"\n[TEST 4] Total: {file_count} files across {len(TEST_DIRS)} folders")
print("[TEST 4] Waiting 5 seconds then cleaning up...")
time.sleep(5)

for d in TEST_DIRS:
    shutil.rmtree(d, ignore_errors=True)
print("[TEST 4] All cleaned up.")
