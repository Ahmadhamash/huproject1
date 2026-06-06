# 🛡️ RansomShield v22 — Real-Time Ransomware Detection Agent

> نظام كشف رانسوموير متعدد الطبقات (10 طبقات) يعمل بالزمن الحقيقي على Windows  
> يعتمد على Sysmon + Machine Learning + Honeypots + Copy-on-Write Recovery

---

## ⚡ التشغيل السريع (أقل من 5 دقائق)

```powershell
# 1. افتح PowerShell كـ Administrator (كليك يمين → Run as Administrator)

# 2. ثبّت المكتبات
pip install pywin32 psutil joblib pandas numpy scikit-learn pefile

# 3. حمّل وثبّت Sysmon (مرة واحدة)
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "$env:TEMP\Sysmon.zip"
Expand-Archive "$env:TEMP\Sysmon.zip" -DestinationPath "$env:TEMP\Sysmon" -Force
Copy-Item "$env:TEMP\Sysmon\Sysmon64.exe" "C:\Windows\Sysmon64.exe" -Force

# 4. ادخل مجلد المشروع وثبّت إعدادات Sysmon
cd "مسار_مجلد_المشروع"
Sysmon64.exe -accepteula -i sysmon_config.xml

# 5. شغّل!
python agent_v22.py --verbose
```

---

## 📋 جدول المحتويات

- [المتطلبات](#-المتطلبات)
- [التثبيت خطوة بخطوة على VM](#-التثبيت-خطوة-بخطوة-على-vm)
- [التحقق من التثبيت](#-التحقق-من-التثبيت)
- [التشغيل](#-التشغيل)
- [اختبار الكشف](#-اختبار-الكشف)
- [اختبار برانسوموير حقيقي](#-اختبار-برانسوموير-حقيقي-على-vm)
- [طبقات الحماية (10 طبقات)](#-طبقات-الحماية)
- [الإعدادات والعتبات](#-الإعدادات-والعتبات)
- [بنية المشروع](#-بنية-المشروع)
- [استكشاف الأخطاء](#-استكشاف-الأخطاء)

---

## 📌 المتطلبات

| المتطلب | الحد الأدنى | ملاحظات |
|---------|-------------|---------|
| **نظام التشغيل** | Windows 10/11 (64-bit) | يفضّل على VM منعزلة |
| **Python** | 3.8+ | يفضل 3.10 أو أحدث |
| **RAM** | 4 GB+ | COW يستهلك حتى 512MB |
| **Sysmon** | v14+ | من Microsoft Sysinternals |
| **صلاحيات** | Administrator | مطلوب لقراءة Event Log |

---

## 🖥️ التثبيت خطوة بخطوة على VM

### الخطوة 0: تجهيز الـ VM

> ⚠️ **مهم جداً:** اختبر الرانسوموير **فقط** داخل VM معزولة!

1. حمّل [VirtualBox](https://www.virtualbox.org/) أو [VMware Workstation Player](https://www.vmware.com/products/workstation-player.html)
2. حمّل Windows 10/11 ISO من [Microsoft](https://www.microsoft.com/software-download/windows10ISO)
3. أنشئ VM جديدة:
   - **RAM:** 4GB+
   - **Disk:** 60GB+
   - **Network:** ❌ **أطفئ الشبكة!** (Host-Only أو Disconnected)
4. ثبّت Windows عليها
5. **خذ Snapshot** قبل أي اختبار (لتقدر ترجّع بعد الرانسوموير)

```
VM Settings → Network → Attached to: "Not attached"  أو  "Host-only Adapter"
```

---

### الخطوة 1: تثبيت Python

```powershell
# داخل الـ VM — حمّل Python من الموقع الرسمي
# https://www.python.org/downloads/

# أثناء التثبيت ✅ فعّل "Add Python to PATH"

# تحقق:
python --version
# المتوقع: Python 3.10+ أو أحدث
```

---

### الخطوة 2: تثبيت المكتبات

```powershell
# افتح PowerShell كـ Administrator
pip install pywin32 psutil joblib pandas numpy scikit-learn pefile
```

| المكتبة | الوظيفة |
|---------|---------|
| `pywin32` | قراءة Windows Event Log (Sysmon events) |
| `psutil` | معلومات العمليات + قتل العمليات المشبوهة |
| `joblib` | تحميل نماذج ML المدرّبة (.pkl) |
| `pandas` | معالجة البيانات واستخراج Features |
| `numpy` | عمليات حسابية |
| `scikit-learn` | نموذج Random Forest للكشف |
| `pefile` | تحليل PE headers (Layer 0 static analysis) |

**تحقق من التثبيت:**

```powershell
python -c "import win32evtlog, psutil, joblib, pandas, numpy, pefile; print('All OK')"
```

---

### الخطوة 3: تثبيت Sysmon

Sysmon أداة مراقبة من Microsoft — **بدونه الأداة ما تشتغل.**

```powershell
# تحميل Sysmon
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "$env:TEMP\Sysmon.zip"

# فك الضغط
Expand-Archive "$env:TEMP\Sysmon.zip" -DestinationPath "$env:TEMP\Sysmon" -Force

# نسخ للنظام
Copy-Item "$env:TEMP\Sysmon\Sysmon64.exe" "C:\Windows\Sysmon64.exe" -Force
```

---

### الخطوة 4: نقل ملفات المشروع للـ VM

انقل مجلد المشروع كامل للـ VM عبر **Shared Folder** أو **USB**:

```
ملفات مطلوبة:
├── agent_v22.py                  ← الكود الرئيسي
├── ransomshield_complete.pkl     ← نموذج ML (59MB)
├── ransomware_rf_model.pkl       ← نموذج L0 (1.5MB)
├── sysmon_config.xml             ← إعدادات Sysmon
└── test_scripts/                 ← اختبارات المحاكاة
```

---

### الخطوة 5: تطبيق إعدادات Sysmon

```powershell
# ادخل مجلد المشروع
cd "C:\RansomShield"   # أو أي مسار نسخت فيه الملفات

# أول مرة (تثبيت + إعدادات):
Sysmon64.exe -accepteula -i sysmon_config.xml

# تحديث إعدادات فقط (إذا Sysmon مثبت من قبل):
Sysmon64.exe -c sysmon_config.xml
```

---

## ✅ التحقق من التثبيت

```powershell
# 1. Sysmon شغّال؟
sc query Sysmon64
# المطلوب: STATE = 4  RUNNING

# 2. الأحداث تتسجّل؟
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 3
# المطلوب: يعرض أحداث بدون أخطاء

# 3. المكتبات شغّالة؟
python -c "import win32evtlog, psutil, joblib; print('OK')"

# 4. النماذج موجودة؟
dir *.pkl
# المطلوب: ransomshield_complete.pkl + ransomware_rf_model.pkl
```

**إذا Sysmon واقف:**
```powershell
net start Sysmon64
```

---

## 🎯 التشغيل

> ⚠️ شغّل **دائماً** كـ Administrator

### وضع المراقبة (Monitoring — للاختبار)

```powershell
cd "C:\RansomShield"

# مراقبة فقط — ما يقتل شيء (أول اختبار)
python agent_v22.py --verbose

# مراقبة مع تفاصيل كاملة + بدون honeypot
python agent_v22.py --verbose --no-honeypot
```

### وضع الحماية (Protection — يقتل الرانسوموير!)

```powershell
# ⚠️ هذا يقتل أي بروسس مشبوه فعلياً!
python agent_v22.py --unlock-kill --verbose

# مع مدة محددة (300 ثانية)
python agent_v22.py --unlock-kill --verbose --duration 300
```

### وضع التسجيل (Recording — لتدريب ML)

```powershell
# تسجيل جلسة سلوك طبيعي
python agent_v22.py --record-mode C:\data\benign.csv --label benign

# تسجيل جلسة رانسوموير
python agent_v22.py --record-mode C:\data\ransom.csv --label ransomware
```

### خيارات إضافية

| الخيار | الوظيفة |
|--------|---------|
| `--verbose` | عرض كل الأحداث بالتفصيل |
| `--unlock-kill` | تفعيل قتل العمليات المشبوهة |
| `--no-honeypot` | تعطيل ملفات Honeypot |
| `--duration N` | إيقاف تلقائي بعد N ثانية |
| `--model PATH` | تحديد مسار نموذج ML |
| `--l0-model PATH` | تحديد مسار نموذج L0 |

---

## 🧪 اختبار الكشف (سكربتات آمنة)

### تشغيل كل الاختبارات

```powershell
# نافذة 1: شغّل الـ Agent
python agent_v22.py --verbose

# نافذة 2: شغّل كل الاختبارات
python test_scripts\run_all_tests.py
```

### تشغيل اختبار واحد

```powershell
# نافذة 2: شغّل اختبار محدد
python test_scripts\test5_slow_ransomware.py
python test_scripts\test9_random_extension.py
```

### الاختبارات المتوفرة

| الاختبار | ماذا يحاكي | الطبقة المتوقعة | المدة |
|----------|-----------|----------------|-------|
| `test5_slow_ransomware.py` | تشفير بطيء (ملف كل 5 ثواني) | L2f: SLOW RANSOM | ~90s |
| `test6_partial_ransomware.py` | تشفير انتقائي (ملفات محددة) | L2b: RANSOM EXT | ~30s |
| `test7_staged_attack.py` | هجوم متعدد المراحل (temp→user) | L2f + bridge | ~50s |
| `test8_wiper.py` | حذف جماعي بدون تشفير | L2c: MASS DELETE | ~20s |
| `test9_random_extension.py` | امتدادات عشوائية (.x7k3m) | L2g: NOVEL EXT | ~25s |
| `test10_double_extortion.py` | نسخ + تشفير (double extortion) | L2b/L2f | ~40s |
| `test11_intermittent.py` | تشفير متقطع (burst-pause-burst) | L2a/L2b | ~120s |

---

## 🦠 اختبار برانسوموير حقيقي على VM

> ⚠️ **تحذير:** هذه عينات خبيثة حقيقية — **فقط** على VM معزولة بدون شبكة!

### تجهيز الـ VM للاختبار الحقيقي

```
1. ✅ خذ Snapshot للـ VM قبل أي شيء!
2. ✅ أطفئ الشبكة (Network: Not Attached)
3. ✅ أطفئ Shared Folders
4. ✅ شغّل RansomShield أولاً
5. ⚠️ شغّل الرانسوموير
6. ✅ راقب الكشف في نافذة الـ Agent
7. ✅ بعد الانتهاء: ارجع للـ Snapshot
```

### مصادر عينات رانسوموير حقيقية

#### 1. MalwareBazaar (الأفضل — مجاني)
- **الرابط:** https://bazaar.abuse.ch/
- **كيف تستخدمه:**
  1. اذهب للموقع
  2. ابحث عن: `tag:ransomware`
  3. أو فلتر حسب العائلة: LockBit, Conti, BlackCat, STOP/Djvu, Phobos
  4. حمّل العينة (ملف مضغوط، الباسورد: `infected`)
  5. انقلها للـ VM عبر USB أو shared folder ثم أطفئ المشاركة

```
بحث مقترح:
- tag:lockbit
- tag:conti  
- tag:blackcat
- tag:stop-djvu
- tag:phobos
- tag:ransomware file_type:exe
```

#### 2. VirusTotal (للبحث والتحليل)
- **الرابط:** https://www.virustotal.com/
- تحتاج حساب premium لتحميل العينات
- ممتاز للتحقق من عينات قبل الاختبار

#### 3. theZoo (GitHub)
- **الرابط:** https://github.com/ytisf/theZoo
- مستودع عينات malware مفتوح المصدر
- فيه عينات رانسوموير كلاسيكية (WannaCry, Petya, GoldenEye)
- الباسورد: `infected`

```powershell
# داخل الـ VM فقط!
git clone https://github.com/ytisf/theZoo.git
cd theZoo/malwares/Binaries
# كل عائلة بمجلد منفصل — الباسورد: infected
```

#### 4. Malware Samples (GitHub)
- https://github.com/HynekPetrak/malware-samples
- https://github.com/vxunderground/MalwareSourceCode (كود مصدري)

#### 5. ANY.RUN (تحليل تفاعلي)
- **الرابط:** https://any.run/
- يعرض سلوك الرانسوموير بالتفصيل قبل ما تحمّله
- ممتاز لفهم كيف يشتغل كل نوع

#### 6. Hybrid Analysis
- **الرابط:** https://www.hybrid-analysis.com/
- ابحث: `ransomware verdict:malicious`
- يعطيك تقرير سلوكي كامل

### عائلات رانسوموير موصى باختبارها

| العائلة | النوع | الصعوبة | ماذا يختبر |
|---------|-------|---------|-----------|
| **STOP/Djvu** | امتداد معروف (.djvu, .stop) | سهل | L2b |
| **WannaCry** | .wcry + SMB spread | سهل | L2b + L2d |
| **LockBit 3.0** | سريع جداً + VSS delete | متوسط | L2a + L2d |
| **BlackCat/ALPHV** | يغيّر أسماء الملفات بالكامل | متوسط | L2g + L2f |
| **Conti** | multi-threaded + exfiltration | صعب | L2a + L2c |
| **Phobos** | بطيء + selective | متوسط | L2f |
| **Hive** | random extension | متوسط | L2g |
| **Royal** | partial encryption | صعب | L2f + L2e |

### خطوات الاختبار الآمن

```powershell
# 1. على الـ VM — تأكد الشبكة مطفية
# 2. خذ Snapshot!
# 3. شغّل الـ Agent بنافذة Admin:
python agent_v22.py --unlock-kill --verbose

# 4. بنافذة ثانية — شغّل الرانسوموير:
# (مثال — المسار يختلف حسب وين حطيت العينة)
.\malware_sample.exe

# 5. راقب نافذة الـ Agent — لازم يكشف ويقتل!
# المتوقع:
#   [!!! RANSOMWARE] PID=XXXX name=malware_sample.exe ...
#   [X] KILLED: malware_sample.exe (PID XXXX) + N children

# 6. بعد الانتهاء — ارجع للـ Snapshot:
# VM → Snapshots → Restore
```

---

## 🏗️ طبقات الحماية (10 طبقات)

```
┌─────────────────────────────────────────────────────┐
│  L0   Static PE Analysis                            │
│  فحص كل .exe جديد (7 features من PE header)        │
├─────────────────────────────────────────────────────┤
│  L1   Honeypot Traps                                │
│  ملفات فخ واقعية (Budget_2025, Tax_Return...)       │
│  أي لمسة = RANSOMWARE فوري (score=1.0)             │
├─────────────────────────────────────────────────────┤
│  L2a  Rename Burst                                  │
│  حذف + إنشاء بامتداد مختلف ≥ 2 مرات (1 ثانية)     │
├─────────────────────────────────────────────────────┤
│  L2b  Known Ransom Extensions                       │
│  30+ امتداد معروف (.encrypted, .locked, .conti...) │
├─────────────────────────────────────────────────────┤
│  L2c  Mass Delete                                   │
│  حذف ≥ 20 ملف بسرعة ≥ 3/ثانية في user data        │
├─────────────────────────────────────────────────────┤
│  L2d  VSS/BCDEdit Escalation                        │
│  حذف Shadow Copies أو تعطيل Recovery                │
├─────────────────────────────────────────────────────┤
│  L2e  In-Place Encryption                           │
│  تعديل timestamps بدون create/delete (overwrite)    │
├─────────────────────────────────────────────────────┤
│  L2f  Slow Ransomware                               │
│  تراكم بطيء (≥10 ثواني + امتدادات/rename)           │
├─────────────────────────────────────────────────────┤
│  L2g  Novel/Anomalous Extensions                    │
│  امتدادات غريبة (.x7k3m) تتكرر ≥3 مرات            │
├─────────────────────────────────────────────────────┤
│  L3   ML Full (18 features + Random Forest)         │
│  نموذج مدرّب + عتبات تكيّفية (Adaptive Engine)     │
├─────────────────────────────────────────────────────┤
│  COW  Copy-on-Write Recovery                        │
│  نسخة احتياطية بالذاكرة — استرجاع فوري!            │
└─────────────────────────────────────────────────────┘
```

---

## ⚙️ الإعدادات والعتبات

### التوقيتات

| الإعداد | القيمة | الوصف |
|---------|--------|-------|
| `STARTUP_GRACE` | 3 ثواني | فترة سماح بعد التشغيل |
| `WINDOW_FAST` | 1 ثانية | نافذة L2a/L2b/L2g |
| `WINDOW_MASS_DEL` | 2 ثانية | نافذة L2c |
| `WINDOW_ML` | 3 ثواني | نافذة L3 ML |
| `WINDOW_RESET` | 20 ثانية | إعادة تعيين النافذة (مع preserve) |
| `POLL_MS` | 0.1 ثانية | استجابة سريعة |
| `COW_ACTIVATE_THRESHOLD` | 5 لمسات | عتبة COW لمسح المجلد كامل |

### العتبات

| الإعداد | القيمة | الوصف |
|---------|--------|-------|
| `THRESHOLD_FAST` | 0.55 | حد ML لـ Rename Burst |
| `THRESHOLD_RANSOM` | 0.60 | حد ML للكشف الكامل |
| `THRESHOLD_SUSPICIOUS` | 0.45 | حد التنبيه |
| `RANSOM_EXT_MIN` | 3 | أقل عدد امتدادات رانسوموير |
| `MASS_DELETE_MIN` | 20 | أقل عدد ملفات محذوفة |

---

## 📁 بنية المشروع

```
📦 RansomShield v22
├── 🐍 agent_v22.py                  # الكود الرئيسي (1730 سطر)
├── 🤖 ransomshield_complete.pkl     # نموذج ML Layer 2 (59MB)
├── 🤖 ransomware_rf_model.pkl       # نموذج ML Layer 0 (1.5MB)
├── ⚙️ sysmon_config.xml             # إعدادات Sysmon المحسّنة
├── 📖 README.md                     # هذا الملف
└── 🧪 test_scripts/
    ├── run_all_tests.py             # مشغّل كل الاختبارات
    ├── test5_slow_ransomware.py     # تشفير بطيء
    ├── test6_partial_ransomware.py  # تشفير انتقائي
    ├── test7_staged_attack.py       # هجوم متعدد المراحل
    ├── test8_wiper.py               # حذف جماعي
    ├── test9_random_extension.py    # امتدادات عشوائية
    ├── test10_double_extortion.py   # نسخ + تشفير
    └── test11_intermittent.py       # تشفير متقطع
```

### الملفات التي تُنشأ تلقائياً

```
~/.ransomshield/
├── ransomshield.log          # ملف الـ Log
├── adaptive_profile.json     # بروفايل الجهاز (Adaptive Engine)
```

---

## 📊 الأحداث المراقبة (Sysmon)

| Event ID | الوصف | الأهمية |
|----------|-------|---------|
| **1** | Process Create | كشف vssadmin/bcdedit |
| **2** | File Time Changed | L2e: In-Place Encryption |
| **3** | Network Connection | رصد اتصالات |
| **5** | Process Terminated | تنظيف COW |
| **11** | File Create | ⭐ إنشاء ملفات + امتدادات رانسوموير |
| **12, 13, 14** | Registry Events | كشف Run keys |
| **17, 18** | Pipe Events | Named Pipes |
| **23** | File Delete Archived | ⭐ كشف الحذف الجماعي |
| **26** | File Delete Detected | ⭐ كشف الحذف |

---

## 🔧 استكشاف الأخطاء

### ❌ "Sysmon not found"

```powershell
# تثبيت Sysmon
Sysmon64.exe -accepteula -i sysmon_config.xml

# تشغيل إذا واقف
net start Sysmon64
```

### ❌ "No module named 'win32evtlog'"

```powershell
pip install pywin32
# أعد تشغيل PowerShell بعدها
```

### ❌ "Access Denied"

- تأكد تشغّل PowerShell كـ **Administrator**
- كليك يمين → **Run as Administrator**

### ❌ النموذج ما يتحمّل

```powershell
# تأكد الملفات موجودة:
dir *.pkl

# المطلوب:
# ransomshield_complete.pkl  (59 MB)
# ransomware_rf_model.pkl   (1.5 MB)
```

### ❌ الكشف بطيء أو ما يكشف

```powershell
# 1. تحقق أن Sysmon يسجّل
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5

# 2. أعد تطبيق الإعدادات
Sysmon64.exe -c sysmon_config.xml

# 3. تأكد من الصلاحيات
whoami /groups | findstr "Administrators"
```

### ❌ COW يستهلك ذاكرة كثير

COW يحفظ حتى 512MB بالذاكرة. لتقليل:
```python
# في الكود، غيّر MAX_TOTAL_MB:
cow = CowProtector(enabled=True, max_mb=256)  # بدل 512
```

---

## 📊 الـ 18 Feature للـ ML

| # | Feature | الوصف |
|---|---------|-------|
| 1 | `files_created_count` | عدد الملفات المنشأة |
| 2 | `files_deleted_count` | عدد الملفات المحذوفة |
| 3 | `registry_sets_count` | عدد عمليات الريجستري |
| 4 | `process_creates_count` | عدد العمليات المنشأة |
| 5 | `net_events_count` | عدد أحداث الشبكة |
| 6 | `unique_dirs_touched` | عدد المجلدات المختلفة |
| 7 | `rename_patterns_count` | أنماط إعادة التسمية |
| 8 | `ransom_ext_count` | امتدادات رانسوموير |
| 9 | `files_created_per_sec` | معدل إنشاء/ثانية |
| 10 | `files_deleted_per_sec` | معدل حذف/ثانية |
| 11 | `delete_to_create_ratio` | نسبة الحذف/الإنشاء |
| 12 | `user_data_ops_ratio` | نسبة عمليات user data |
| 13 | `temp_ops_ratio` | نسبة عمليات temp |
| 14 | `started_in_temp` | هل بدأ من temp |
| 15 | `temp_to_user_bridge` | temp → user data bridge |
| 16 | `vss_delete_seen` | حذف Shadow Copies |
| 17 | `bcdedit_seen` | تعطيل Recovery |
| 18 | `run_key_written` | كتابة Run key |

---

## 📜 الرخصة

هذا المشروع للاستخدام **البحثي والتعليمي فقط**.  
لا تستخدم عينات رانسوموير حقيقية خارج بيئة معزولة (VM).

---

> **RansomShield v22** — 10 Detection Layers | ML + Behavioral Analysis | Real-Time Protection
