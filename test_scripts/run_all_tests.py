"""
Test Runner — يشغّل كل الاختبارات بالتسلسل ويعطيك ملخص
استخدام:
  python test_scripts/run_all_tests.py

تأكد إن agent_v22.py شغال بنافذة ثانية مع --verbose:
  python agent_v22.py --verbose
"""
import subprocess, sys, time, os

TESTS = [
    ("Test 5 — Slow Ransomware",       "test5_slow_ransomware.py",   90),
    ("Test 6 — Partial/Selective",      "test6_partial_ransomware.py", 30),
    ("Test 7 — Multi-Stage Attack",     "test7_staged_attack.py",     50),
    ("Test 8 — Wiper (No Encryption)",  "test8_wiper.py",             20),
    ("Test 9 — Random Extensions",      "test9_random_extension.py",  20),
    ("Test 10 — Double Extortion",      "test10_double_extortion.py", 40),
    ("Test 11 — Intermittent Burst",    "test11_intermittent.py",     120),
]

script_dir = os.path.dirname(os.path.abspath(__file__))

print("=" * 70)
print("  RANSOMSHIELD TEST RUNNER — Comprehensive Detection Tests")
print(f"  Tests: {len(TESTS)}")
print(f"  Make sure agent_v22.py is running with --verbose in another window!")
print("=" * 70)

input("\n  Press ENTER to start all tests (or Ctrl+C to cancel)...\n")

results = []
for name, script, timeout in TESTS:
    print(f"\n{'='*70}")
    print(f"  >> Starting: {name}")
    print(f"     Script: {script} (timeout: {timeout}s)")
    print(f"{'='*70}\n")

    script_path = os.path.join(script_dir, script)
    start = time.time()

    try:
        proc = subprocess.run(
            [sys.executable, script_path],
            timeout=timeout + 30,
            capture_output=False,
        )
        elapsed = time.time() - start
        status = "PASS" if proc.returncode == 0 else f"FAIL (exit={proc.returncode})"
    except subprocess.TimeoutExpired:
        elapsed = timeout + 30
        status = "TIMEOUT"
    except Exception as e:
        elapsed = time.time() - start
        status = f"ERROR: {e}"

    results.append((name, status, elapsed))
    print(f"\n  >> {name}: {status} ({elapsed:.1f}s)")

    # فاصل بين الاختبارات عشان الـ Agent يعيد ضبط النوافذ
    print(f"\n  Waiting 10 seconds before next test...")
    time.sleep(10)

# ── ملخص النتائج ─────────────────────────────────────
print(f"\n\n{'='*70}")
print(f"  RESULTS SUMMARY")
print(f"{'='*70}")
for name, status, elapsed in results:
    icon = "OK" if "PASS" in status else "XX"
    print(f"  [{icon}] {name:35} {status:15} {elapsed:.1f}s")

total_time = sum(e for _, _, e in results)
print(f"\n  Total time: {total_time:.0f}s ({total_time/60:.1f} minutes)")
print(f"  Check agent_v22.py output for detection results!")
print(f"{'='*70}")
