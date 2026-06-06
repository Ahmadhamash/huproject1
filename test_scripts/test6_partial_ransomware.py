"""
Test 6: PARTIAL Ransomware (Selective Targeting)
يحاكي رانسوموير يشفّر بس أنواع معينة من الملفات (documents فقط)
ويتجاهل الصور والفيديوهات — يركّز على الملفات ذات القيمة العالية
🎯 الطبقة المستهدفة: L2a (Rename) + L2b (Extensions) + L3 (ML)
"""
import os, time, shutil

BASE = os.path.expanduser("~")
TEST_DIR = os.path.join(BASE, "Documents", "_ransomshield_test6_partial")
os.makedirs(TEST_DIR, exist_ok=True)

# إنشاء مجلدات فرعية تحاكي بنية ملفات حقيقية
SUBDIRS = ["Financial", "HR", "Projects", "Personal"]
for sd in SUBDIRS:
    os.makedirs(os.path.join(TEST_DIR, sd), exist_ok=True)

# ملفات مستهدفة (documents) وملفات غير مستهدفة (images)
TARGET_EXTS = [".docx", ".xlsx", ".pdf", ".pptx", ".csv", ".txt"]
IGNORE_EXTS = [".jpg", ".png", ".mp4", ".bmp"]

print("=" * 60)
print("[TEST 6] PARTIAL RANSOMWARE — Selective Targeting")
print(f"  Working in: {TEST_DIR}")
print(f"  Strategy: Only encrypt documents, skip images")
print("=" * 60)

# Phase 1: إنشاء ملفات متنوعة
print("\n[Phase 1] Creating mixed files (documents + images)...")
all_files = []
for sd in SUBDIRS:
    for i in range(8):
        if i < 5:  # 5 documents
            ext = TARGET_EXTS[i % len(TARGET_EXTS)]
            category = "TARGET"
        else:  # 3 images
            ext = IGNORE_EXTS[(i - 5) % len(IGNORE_EXTS)]
            category = "SKIP"

        fp = os.path.join(TEST_DIR, sd, f"{sd.lower()}_file_{i}{ext}")
        with open(fp, "w") as f:
            f.write(f"Data for {sd} department, file {i} " * 150)
        all_files.append((fp, category, ext))
        print(f"  [{category:6}] {sd}/file_{i}{ext}")

print(f"\n  Total: {len(all_files)} files "
      f"({sum(1 for _, c, _ in all_files if c == 'TARGET')} targets, "
      f"{sum(1 for _, c, _ in all_files if c == 'SKIP')} skipped)")

# Phase 2: تشفير انتقائي
print(f"\n[Phase 2] Selective encryption starting in 3 seconds...\n")
time.sleep(3)

encrypted = 0
skipped = 0
for fp, category, orig_ext in all_files:
    if category == "SKIP":
        skipped += 1
        continue

    basename = os.path.splitext(os.path.basename(fp))[0]
    dirname = os.path.dirname(fp)

    os.remove(fp)
    enc_path = os.path.join(dirname, f"{basename}.locked")
    with open(enc_path, "w") as f:
        f.write("SELECTIVELY_ENCRYPTED_DOCUMENT")

    encrypted += 1
    print(f"  [ENC {encrypted:2d}] {basename}{orig_ext} -> {basename}.locked")
    time.sleep(0.2)

print(f"\n[TEST 6] ✅ Done! Encrypted: {encrypted}, Skipped: {skipped}")
print("[TEST 6] Cleaning up in 5 seconds...")
time.sleep(5)
shutil.rmtree(TEST_DIR, ignore_errors=True)
print("[TEST 6] Cleaned.")
