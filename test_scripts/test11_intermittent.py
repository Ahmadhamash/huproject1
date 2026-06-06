"""
Test 11: INTERMITTENT Ransomware (Burst-Pause-Burst)
يحاكي رانسوموير يشتغل بدفعات: يشفّر 5 ملفات بسرعة → يوقف 15 ثانية → يكمل
يحاول يتهرب من كشف النافذة الثابتة (WINDOW_RESET)
🎯 الطبقة: يختبر هل WINDOW_RESET يمسح الإشارات بين الدفعات
⏱️ المدة: ~2 دقيقة
"""
import os, time, shutil

TEST_DIR = os.path.join(os.path.expanduser("~"), "Documents",
                        "_ransomshield_test11_intermittent")
os.makedirs(TEST_DIR, exist_ok=True)

BURST_SIZE = 5
PAUSE_SEC = 15
NUM_BURSTS = 4

print("=" * 60)
print("[TEST 11] INTERMITTENT RANSOMWARE — Burst-Pause-Burst")
print(f"  Working in: {TEST_DIR}")
print(f"  Strategy: {BURST_SIZE} files fast, pause {PAUSE_SEC}s, repeat {NUM_BURSTS}x")
print("=" * 60)

# Phase 1: إنشاء كل الملفات مقدماً
total_files = BURST_SIZE * NUM_BURSTS
print(f"\n[Phase 1] Creating {total_files} target files...")
files = []
EXTS = [".docx", ".xlsx", ".pdf", ".jpg", ".txt"]
for i in range(total_files):
    ext = EXTS[i % len(EXTS)]
    fp = os.path.join(TEST_DIR, f"archive_{i:03d}{ext}")
    with open(fp, "w") as f:
        f.write(f"Archive record #{i} " * 200)
    files.append(fp)

print(f"  Created {total_files} files")

# Phase 2: Burst-Pause-Burst
print(f"\n[Phase 2] Starting intermittent encryption...\n")
time.sleep(3)

for burst in range(NUM_BURSTS):
    start_idx = burst * BURST_SIZE
    end_idx = start_idx + BURST_SIZE
    burst_files = files[start_idx:end_idx]

    print(f"  ┌── BURST {burst + 1}/{NUM_BURSTS} "
          f"(files {start_idx + 1}-{end_idx}) ──")

    for i, fp in enumerate(burst_files):
        basename = os.path.splitext(os.path.basename(fp))[0]
        orig_ext = os.path.splitext(fp)[1]

        os.remove(fp)
        enc = os.path.join(TEST_DIR, f"{basename}.locked")
        with open(enc, "w") as f:
            f.write("INTERMITTENT_ENCRYPTED")

        print(f"  │ [{start_idx + i + 1:2d}/{total_files}] "
              f"{basename}{orig_ext} -> .locked")
        time.sleep(0.1)  # سرعة عالية داخل الدفعة

    if burst < NUM_BURSTS - 1:
        print(f"  └── PAUSE {PAUSE_SEC} seconds (evading detection)...")
        time.sleep(PAUSE_SEC)
    else:
        print(f"  └── DONE")

print(f"\n[TEST 11] ✅ Intermittent attack complete!")
print(f"  Total encrypted: {total_files}")
print(f"  Bursts: {NUM_BURSTS} × {BURST_SIZE} files")
print(f"  Pause between bursts: {PAUSE_SEC}s")
print("\n[TEST 11] Cleaning up in 5 seconds...")
time.sleep(5)
shutil.rmtree(TEST_DIR, ignore_errors=True)
print("[TEST 11] Cleaned.")
