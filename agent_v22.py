"""
RansomShield Layer 2 v22 — Data-Capable Build

تغييرات v22 عن v21:
  1. Feature extractor جديد (18 feature): counts + rates + ratios + strong indicators
     (بدل flags ثنائية كانت تُضيّع المعلومة)
  2. --record-mode: يسجّل snapshots من نفس الـ agent لبناء داتاست تدريب
     ⇒ هذا يضمن أن مصدر التدريب = مصدر الإنتاج (نفس الـ pipeline)
  3. Smart labeling: في جلسة ransomware، النوافذ قبل أول trigger تُعلَّم -1 (تُرمى)،
     والنوافذ بعد الـ trigger تُعلَّم 1
  4. Temp/cache logic: أحداثها تُحصى بشكل منفصل، وترفع الخطورة فقط عند
     "bridge" (عمليات في temp ثم في user data) أو ransom extension
  5. CommandLine parsing: كشف vssadmin / wmic shadowcopy / bcdedit disable recovery
  6. Registry Run key detection: كتابة على HKLM/HKCU Run/RunOnce
  7. الفحوصات القاعدية (L1-L2c) محفوظة من v21 للاستخدام في الإنتاج

Usage:
  # وضع التسجيل على جلسة benign
  python agent_v22.py --record-mode C:\\data\\benign_session_01.csv --label benign \\
                      --session benign_win10_chrome_office

  # وضع التسجيل على جلسة ransomware (المودل ما بيقتل، فقط يسجّل)
  python agent_v22.py --record-mode C:\\data\\ransom_lockbit_01.csv --label ransomware \\
                      --session ransomware_lockbit_3

  # وضع الإنتاج (لما يكون عندك مودل مدرَّب)
  python agent_v22.py --unlock-kill
"""

import time, sys, os, math, subprocess, argparse, threading, json, hashlib, logging
import datetime as dt
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

import pandas as pd
import numpy as np

try:
    import win32evtlog
    import psutil
    import joblib
    import pefile
    WINDOWS_AVAILABLE = True
except ImportError:
    WINDOWS_AVAILABLE = False

# ══════════════════════════════════════════════════════════
# Timing & Thresholds
# ══════════════════════════════════════════════════════════
STARTUP_GRACE     = 3.0     # تقليل من 8 لـ 3 لكشف أسرع
WINDOW_FAST       = 1.0
WINDOW_RANSOM_EXT = 1.0
WINDOW_MASS_DEL   = 2.0
WINDOW_ML         = 3.0     # تقليل من 5 لـ 3 لكشف أسرع
WINDOW_RESET      = 20.0    # تقليل من 30 لـ 20
POLL_MS           = 0.1     # استجابة أسرع
SYSMON_CHECK_SEC  = 15

RECORD_INTERVAL   = 5.0   # كم ثانية بين snapshot وsnapshot في وضع التسجيل
RECORD_MIN_AGE    = 1.0   # ما نسجّل PID عمره أقل من كذا

THRESHOLD_FAST       = 0.55
THRESHOLD_RANSOM     = 0.60
THRESHOLD_SUSPICIOUS = 0.45
RANSOM_EXT_MIN       = 3
MASS_DELETE_MIN      = 20
DELETE_RATE_MIN      = 3.0
DEBUG_INTERVAL       = 5.0

# Layer 0 Static
L0_THRESHOLD         = 0.70   # عتبة كشف الملفات الخبيثة ساكنياً
L0_BLOCK_THRESHOLD   = 0.90   # عتبة الحظر التلقائي

# Adaptive Engine
ADAPTIVE_PROFILE_DIR = os.path.join(os.path.expanduser('~'), '.ransomshield')
ADAPTIVE_UPDATE_SEC  = 60     # تحديث البروفايل كل 60 ثانية

# ══════════════════════════════════════════════════════════
# Sysmon event query
# ══════════════════════════════════════════════════════════
LOG_PATH = "Microsoft-Windows-Sysmon/Operational"
NS       = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
QUERY    = ("*[System[(EventID=1 or EventID=2 or EventID=3 or EventID=5 "
            "or EventID=11 or EventID=12 or EventID=13 or EventID=14 "
            "or EventID=17 or EventID=18 or EventID=23 or EventID=26)]]")

IGNORE = {"sysmon.exe", "sysmon64.exe", "agent_v22.exe"}

# COW: عتبة تفعيل الحفظ — بروسس لازم يلمس هالعدد من الملفات بمجلدات user قبل ما نبدأ نحفظ مجلدات كاملة
COW_ACTIVATE_THRESHOLD = 5

# امتدادات معروفة وشائعة — أي امتداد مش بهالقائمة يعتبر "شاذ"
COMMON_EXTENSIONS = {
    # Documents
    '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.pdf', '.odt',
    '.ods', '.odp', '.rtf', '.txt', '.csv', '.md', '.tex', '.log',
    # Images
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.ico', '.tif',
    '.tiff', '.webp', '.psd', '.raw', '.heic', '.heif',
    # Audio/Video
    '.mp3', '.mp4', '.avi', '.mov', '.wav', '.mkv', '.flac', '.aac',
    '.wmv', '.flv', '.m4a', '.ogg', '.webm',
    # Archives
    '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz', '.iso',
    # Code
    '.py', '.js', '.ts', '.c', '.cpp', '.h', '.java', '.cs', '.go',
    '.rs', '.rb', '.php', '.html', '.css', '.json', '.xml', '.yaml',
    '.yml', '.sql', '.sh', '.bat', '.ps1', '.vbs', '.lua', '.r',
    # Executables/Libraries
    '.exe', '.dll', '.sys', '.msi', '.com', '.scr', '.drv',
    # Data
    '.db', '.sqlite', '.mdb', '.accdb', '.bak', '.tmp', '.dat',
    # Config
    '.ini', '.cfg', '.conf', '.reg', '.inf', '.plist',
    # Windows System — اللي كانت تسبب false positives
    '.etl', '.evtx', '.blf', '.regtrans-ms', '.log1', '.log2',
    '.wct', '.dmp', '.mdmp', '.hdmp', '.ndf', '.mdf', '.ldf',
    '.edb', '.stm', '.chk', '.jrs', '.pat', '.cat', '.man',
    '.mui', '.mum', '.sdb', '.ttf', '.ttc', '.otf', '.woff', '.woff2',
    # Application Logs
    '.aodl', '.olk', '.ost', '.pst', '.eml', '.msg', '.nst',
    '.one', '.onepkg', '.onetoc', '.onetoc2',
    # Development
    '.sln', '.csproj', '.pyc', '.class', '.vsctmp', '.suo',
    '.o', '.obj', '.lib', '.a', '.so', '.dylib', '.pdb',
    '.ilk', '.exp', '.idb', '.tlog', '.lastbuildstate',
    # Misc
    '.lnk', '.url', '.desktop', '.cer', '.pem', '.key', '.crt',
    '.cab', '.msp', '.mst', '.manifest', '.config',
}

# ══════════════════════════════════════════════════════════
# Path classification — temp/cache vs user data vs other
# ══════════════════════════════════════════════════════════
TEMP_PATTERNS = (
    '\\appdata\\local\\temp\\',
    '\\windows\\temp\\',
    '\\local\\temp\\',
    '\\appdata\\local\\microsoft\\windows\\inetcache\\',
    '\\appdata\\local\\microsoft\\windows\\webcache\\',
    '\\appdata\\local\\google\\chrome\\user data\\default\\cache',
    '\\appdata\\local\\microsoft\\edge\\user data\\default\\cache',
    '\\appdata\\local\\mozilla\\firefox\\profiles\\',
    '\\programdata\\package cache\\',
    '\\windows\\prefetch\\',
    '\\windows\\softwaredistribution\\download\\',
    '\\windows\\installer\\',
    '\\$recycle.bin\\',
)

USER_DATA_PATTERNS = (
    '\\documents\\', '\\desktop\\', '\\pictures\\',
    '\\videos\\', '\\music\\', '\\downloads\\',
    '\\onedrive\\', '\\dropbox\\', '\\google drive\\',
    '\\box sync\\',
)

RANSOM_EXTENSIONS = {
    '.encrypted', '.enc', '.locked', '.crypted', '.crypt',
    '.wcry', '.wncry', '.locky', '.cerber', '.zepto',
    '.zzzzz', '.aes', '.rsa', '.lock', '.crypto', '.coded',
    '.pays', '.wallet', '.kraken', '.dharma', '.phobos',
    '.deadbolt', '.makop', '.stop', '.djvu', '.ryuk',
    '.conti', '.lockbit', '.blackcat', '.hive', '.cl0p',
    '.babuk', '.lorenz', '.avaddon', '.darkside', '.revil',
}

RUN_KEY_PATTERNS = (
    '\\software\\microsoft\\windows\\currentversion\\run',
    '\\software\\microsoft\\windows\\currentversion\\runonce',
    '\\software\\wow6432node\\microsoft\\windows\\currentversion\\run',
    '\\software\\microsoft\\windows nt\\currentversion\\winlogon',
    '\\system\\currentcontrolset\\services\\',
)


def classify_path(path):
    """Return 'temp', 'user', or 'other' for a given path."""
    if not path:
        return 'other'
    p = path.lower()
    for pat in TEMP_PATTERNS:
        if pat in p:
            return 'temp'
    for pat in USER_DATA_PATTERNS:
        if pat in p:
            return 'user'
    return 'other'


def looks_like_run_key(target_object):
    if not target_object:
        return False
    t = target_object.lower()
    return any(pat in t for pat in RUN_KEY_PATTERNS)


# ══════════════════════════════════════════════════════════
# Feature order — MUST stay stable between record + training + inference
# ══════════════════════════════════════════════════════════
FEATURE_ORDER = [
    # Counts
    'files_created_count',
    'files_deleted_count',
    'registry_sets_count',
    'process_creates_count',
    'net_events_count',
    'unique_dirs_touched',
    'rename_patterns_count',
    'ransom_ext_count',
    # Rates
    'files_created_per_sec',
    'files_deleted_per_sec',
    # Ratios
    'delete_to_create_ratio',
    'user_data_ops_ratio',
    'temp_ops_ratio',
    # Strong indicators
    'started_in_temp',
    'temp_to_user_bridge',
    'vss_delete_seen',
    'bcdedit_seen',
    'run_key_written',
]


def parse_event_time(et_str):
    try:
        return dt.datetime.strptime(et_str[:19].replace('T', ' '),
                                    '%Y-%m-%d %H:%M:%S')
    except Exception:
        return None


# ══════════════════════════════════════════════════════════
class Honeypot:
    NAMES = [
        "Budget_2025_Final.xlsx", "Meeting_Notes_Q4.docx",
        "Tax_Return_2024.pdf", "Family_Photos_Backup.jpg",
        "Resume_Latest.docx", "Invoice_December.pdf",
        "Project_Proposal.pptx"
    ]

    def __init__(self, enabled=True):
        self.enabled    = enabled
        self.trap_files = set()
        self.trap_dirs  = []
        if enabled and WINDOWS_AVAILABLE:
            self._deploy()

    def _deploy(self):
        home = Path.home()
        for d in ['Documents', 'Desktop', 'Pictures']:
            udir = home / d
            if not udir.exists():
                continue
            td = udir / ".ransomshield_traps"
            td.mkdir(exist_ok=True)
            self.trap_dirs.append(td)
            try:
                import ctypes
                ctypes.windll.kernel32.SetFileAttributesW(str(td), 0x02)
            except Exception:
                pass
            for name in self.NAMES:
                for loc in [udir, td]:
                    tp = loc / name
                    if not tp.exists():
                        try:
                            tp.write_text("Confidential Report\n" + "data " * 300)
                        except Exception:
                            pass
                    self.trap_files.add(str(tp).lower())
        if self.trap_files:
            print(f"  [+] Honeypot: {len(self.trap_files)} traps deployed")

    def is_trap(self, fp):
        return self.enabled and fp and fp.lower() in self.trap_files

    def cleanup(self):
        import shutil
        for f in list(self.trap_files):
            try: os.remove(f)
            except Exception: pass
        for d in self.trap_dirs:
            try: shutil.rmtree(d)
            except Exception: pass


# ══════════════════════════════════════════════════════════
class SysmonGuard:
    def __init__(self): self.last = 0

    def check(self):
        if time.time() - self.last < SYSMON_CHECK_SEC:
            return
        self.last = time.time()
        try:
            r = subprocess.run(['sc', 'query', 'Sysmon64'],
                               capture_output=True, text=True, timeout=5)
            if 'RUNNING' not in r.stdout:
                subprocess.run(['net', 'start', 'Sysmon64'],
                               capture_output=True, timeout=10)
                print("  [!] Sysmon restarted.")
        except Exception:
            pass


# ══════════════════════════════════════════════════════════
class Engine:
    """Process behavior tracker — يبني window لكل PID ويستخرج features."""

    def __init__(self, honeypot=None, adaptive=None):
        self.windows    = {}
        self.killed     = set()
        self.killed_times = {}    # pid → timestamp لتنظيف دوري
        self.incidents  = []
        self.honeypot   = honeypot
        self.adaptive   = adaptive
        self.my_pid     = str(os.getpid())
        self.proc_freq  = defaultdict(int)
        self.start_time = time.time()
        self.debug_last = {}
        self.last_killed_cleanup = time.time()

    def _new(self, name="?", image="", parent_image="", parent_pid="",
             preserve=None):
        w = {
            # basic
            'name': name, 'image': image, 'start': time.time(),
            'parent_image': parent_image, 'parent_pid': parent_pid,

            # raw counts — مش flags بعد الآن
            'fc': 0, 'fd': 0, 'ft': 0, 'pc': 0, 'pt': 0,
            'reg': 0, 'net': 0, 'pipe': 0,
            'ft_user': 0,     # file time changes في مجلدات المستخدم

            # per-location counts
            'fc_user': 0, 'fd_user': 0,
            'fc_temp': 0, 'fd_temp': 0,
            'fc_other': 0, 'fd_other': 0,

            # rename tracking
            'deleted_files': {}, 'created_files': {},
            'rename_patterns': 0,
            'ransom_ext_count': 0, 'ransom_ext_seen': '',

            # novel extension tracking — كشف امتدادات شاذة
            'novel_ext_count': 0,       # عدد ملفات بامتدادات شاذة
            'novel_ext_map': {},         # ext → count

            'unique_dirs': set(),

            # strong indicators
            'started_in_temp': 1 if classify_path(image) == 'temp' else 0,
            'had_temp_ops': False,
            'had_user_ops': False,
            'temp_to_user_bridge': 0,
            'vss_delete_seen': 0,
            'bcdedit_seen': 0,
            'run_key_written': 0,

            # trigger tracking (للـ smart labeling)
            'malicious_trigger_time': None,
            'triggers_fired': [],

            # misc
            'last_target': '',
            'total_events': 0,
            'honeypot_hit': False,
        }

        if preserve:
            # نحافظ على الإشارات التراكمية عبر window resets
            for k in ('ransom_ext_count', 'ransom_ext_seen', 'rename_patterns',
                     'vss_delete_seen', 'bcdedit_seen', 'run_key_written',
                     'had_temp_ops', 'had_user_ops', 'temp_to_user_bridge',
                     'malicious_trigger_time', 'triggers_fired',
                     'started_in_temp', 'ft_user', 'honeypot_hit',
                     'fc', 'fd', 'fc_user', 'fd_user',
                     'novel_ext_count', 'novel_ext_map'):
                if k in preserve:
                    w[k] = preserve[k]
            # حفظ قواميس الملفات لتقوية rename detection عبر windows
            for dk in ('deleted_files', 'created_files'):
                if dk in preserve and preserve[dk]:
                    w[dk] = preserve[dk]

        return w

    def add(self, pid, name, image, eid, target,
            parent_img="", parent_pid="", cmd=""):

        if pid == self.my_pid:
            return
        # PID Reuse Protection: تنظيف دوري للـ killed set
        if pid in self.killed:
            # إذا البروسس الحالي مختلف عن اللي قتلناه → PID أُعيد استخدامه
            if pid in self.killed_times:
                if time.time() - self.killed_times[pid] > 60:
                    self.killed.discard(pid)
                    del self.killed_times[pid]
                else:
                    return
            else:
                return
        if pid not in self.windows:
            self.windows[pid] = self._new(name, image, parent_img, parent_pid)

        w = self.windows[pid]
        w['name'] = name
        w['image'] = image
        w['total_events'] += 1

        if target:
            w['last_target'] = target
            d = os.path.dirname(target)
            if d:
                w['unique_dirs'].add(d.lower())

        if parent_img: w['parent_image'] = parent_img
        if parent_pid: w['parent_pid']   = parent_pid

        # Honeypot check
        if (self.honeypot and target
                and self.honeypot.is_trap(target)
                and time.time() - self.start_time > STARTUP_GRACE):
            w['honeypot_hit'] = True

        path_type   = classify_path(target)
        base_no_ext = (os.path.splitext(os.path.basename(target).lower())[0]
                       if target else "")

        # ── File Delete ────────────────────────────────────
        if eid in (23, 26):
            w['fd'] += 1
            if path_type == 'user':
                w['fd_user'] += 1; w['had_user_ops'] = True
            elif path_type == 'temp':
                w['fd_temp'] += 1; w['had_temp_ops'] = True
            else:
                w['fd_other'] += 1

            if base_no_ext:
                w['deleted_files'][base_no_ext] = target
            if base_no_ext in w['created_files']:
                ce = os.path.splitext(w['created_files'][base_no_ext])[1].lower()
                de = os.path.splitext(target)[1].lower()
                if ce != de:
                    w['rename_patterns'] += 1

        # ── File Create ────────────────────────────────────
        elif eid == 11:
            w['fc'] += 1
            if path_type == 'user':
                w['fc_user'] += 1; w['had_user_ops'] = True
            elif path_type == 'temp':
                w['fc_temp'] += 1; w['had_temp_ops'] = True
            else:
                w['fc_other'] += 1

            new_ext = os.path.splitext(target)[1].lower()
            if new_ext in RANSOM_EXTENSIONS:
                w['ransom_ext_count'] += 1
                w['ransom_ext_seen']   = new_ext
            # كشف امتدادات شاذة (مش بالقائمة المعروفة)
            if (new_ext and len(new_ext) > 1
                    and new_ext not in COMMON_EXTENSIONS
                    and new_ext not in RANSOM_EXTENSIONS
                    and path_type == 'user'):
                w['novel_ext_count'] += 1
                w['novel_ext_map'][new_ext] = w['novel_ext_map'].get(new_ext, 0) + 1
            if base_no_ext in w['deleted_files']:
                old_ext = os.path.splitext(
                    w['deleted_files'][base_no_ext])[1].lower()
                if old_ext != new_ext:
                    w['rename_patterns'] += 1
            else:
                w['created_files'][base_no_ext] = target

        # ── Process Create — هنا نكشف vssadmin/wmic/bcdedit ─
        elif eid == 1:
            w['pc'] += 1
            self.proc_freq[name] += 1

            # ننسب هذه الإشارات لـ parent PID (اللي أطلق vssadmin)
            cmd_l = (cmd or "").lower()
            if parent_pid and parent_pid in self.windows:
                pw = self.windows[parent_pid]
                if 'vssadmin' in cmd_l and 'delete' in cmd_l and 'shadow' in cmd_l:
                    pw['vss_delete_seen'] = 1
                elif 'wmic' in cmd_l and 'shadowcopy' in cmd_l and 'delete' in cmd_l:
                    pw['vss_delete_seen'] = 1
                elif 'bcdedit' in cmd_l and (
                        'recoveryenabled no' in cmd_l
                        or 'bootstatuspolicy ignoreallfailures' in cmd_l):
                    pw['bcdedit_seen'] = 1

        elif eid == 5:
            w['pt'] += 1

        elif eid == 3:
            w['net'] += 1

        elif eid == 2:
            w['ft'] += 1
            if classify_path(target) == 'user':
                w['ft_user'] += 1

        # ── Registry set — نكشف Run key modifications ──────
        elif eid in (12, 13, 14):
            w['reg'] += 1
            if looks_like_run_key(target):
                w['run_key_written'] = 1

        elif eid in (17, 18):
            w['pipe'] += 1

        # Update bridge flag
        if w['had_temp_ops'] and w['had_user_ops']:
            w['temp_to_user_bridge'] = 1

    # ──────────────────────────────────────────────────────
    def _extract(self, w, now=None):
        if now is None:
            now = time.time()
        elapsed = max(now - w['start'], 0.1)
        fc, fd = w['fc'], w['fd']
        total_fops = fc + fd

        return {
            # Counts
            'files_created_count':   fc,
            'files_deleted_count':   fd,
            'registry_sets_count':   w['reg'],
            'process_creates_count': w['pc'],
            'net_events_count':      w['net'],
            'unique_dirs_touched':   len(w['unique_dirs']),
            'rename_patterns_count': w['rename_patterns'],
            'ransom_ext_count':      w['ransom_ext_count'],
            # Rates
            'files_created_per_sec': round(fc / elapsed, 3),
            'files_deleted_per_sec': round(fd / elapsed, 3),
            # Ratios
            'delete_to_create_ratio': round(fd / max(fc, 1), 3),
            'user_data_ops_ratio':    round(
                (w['fc_user'] + w['fd_user']) / max(total_fops, 1), 3),
            'temp_ops_ratio':         round(
                (w['fc_temp'] + w['fd_temp']) / max(total_fops, 1), 3),
            # Strong indicators
            'started_in_temp':     w['started_in_temp'],
            'temp_to_user_bridge': w['temp_to_user_bridge'],
            'vss_delete_seen':     w['vss_delete_seen'],
            'bcdedit_seen':        w['bcdedit_seen'],
            'run_key_written':     w['run_key_written'],
        }

    def _score(self, feat, bmodel):
        if not bmodel:
            return 0.0
        try:
            clf    = bmodel['clf']
            scaler = bmodel.get('scaler')
            order  = bmodel.get('features') or FEATURE_ORDER
            values = [feat.get(k, 0) for k in order]
            df_in  = pd.DataFrame([values], columns=order)
            if scaler:
                df_in = pd.DataFrame(scaler.transform(df_in), columns=order)
            return float(clf.predict_proba(df_in)[0][1])
        except Exception as e:
            print(f"  [ERROR] ML: {e}")
            return 0.0


    def _check_trigger(self, w):
        """
        نحدّد لحظة أول إشارة "حقيقية" لسلوك ransomware.
        نستخدم هذه اللحظة لتمييز النوافذ قبل/بعد الهجوم في وضع التسجيل.
        """
        if w['malicious_trigger_time'] is not None:
            return  # triggered قبل، ما نغيّر الوقت

        triggers = []
        if w['ransom_ext_count'] >= 1:
            triggers.append('ransom_ext')
        if w['rename_patterns'] >= 2:
            triggers.append('rename_burst')
        if w['fd_user'] >= 10:
            triggers.append('mass_delete_user')
        if w['vss_delete_seen']:
            triggers.append('vss_delete')
        if w['bcdedit_seen']:
            triggers.append('bcdedit_disable_recovery')
        if w['honeypot_hit']:
            triggers.append('honeypot')
        if w.get('novel_ext_count', 0) >= 3:
            triggers.append('novel_extension')

        if triggers:
            w['malicious_trigger_time'] = time.time()
            w['triggers_fired']         = triggers

    def _report(self, pid, w, decision, score, confidence, reason):
        r = {'pid': pid, 'name': w['name'], 'decision': decision,
             'score': round(score, 3), 'confidence': confidence,
             'reason': reason, 'image': w.get('image', ''),
             'time': datetime.now().isoformat()}
        if decision == "RANSOMWARE":
            self.killed.add(pid)
            self.killed_times[pid] = time.time()
            self.incidents.append(r)
        return r

    @staticmethod
    def _has_real_signal(w):
        return (w['ransom_ext_count'] > 0 or w['rename_patterns'] > 0
                or w['fd'] > 3 or w['fc'] > 5
                or w['vss_delete_seen'] or w['bcdedit_seen']
                or w.get('novel_ext_count', 0) >= 3)

    # ══════════════════════════════════════════════════════
    def evaluate(self, bmodel=None):
        """Production evaluation loop — نفس v21 بس بـ features الجديدة."""
        results = []
        now = time.time()

        for pid in list(self.windows.keys()):
            w = self.windows[pid]
            elapsed = now - w['start']

            # L1: Honeypot
            if w['honeypot_hit']:
                self._check_trigger(w)
                results.append(self._report(
                    pid, w, 'RANSOMWARE', 1.0, 'CRITICAL', 'HONEYPOT TRAP'))
                del self.windows[pid]; continue

            # L2a: Rename Burst
            if elapsed >= WINDOW_FAST and w['rename_patterns'] >= 2:
                self._check_trigger(w)
                feat   = self._extract(w, now)
                bscore = self._score(feat, bmodel)
                # Fallback: إذا ML مش موجود، نستخدم score حسابي — بس فقط لو في عمليات user
                if bscore == 0.0 and not bmodel:
                    if w['had_user_ops']:
                        bscore = min(0.55 + (w['rename_patterns'] - 2) * 0.10, 0.95)
                    else:
                        bscore = 0.0  # rename بمجلدات نظام — مش رانسوموير
                if bscore >= THRESHOLD_FAST:
                    results.append(self._report(
                        pid, w, 'RANSOMWARE', bscore, 'HIGH',
                        f'RENAME BURST ×{w["rename_patterns"]} ML={bscore:.2f}'))
                    del self.windows[pid]; continue

            # L2b: Ransom Extension
            if (elapsed >= WINDOW_RANSOM_EXT
                    and w['ransom_ext_count'] >= RANSOM_EXT_MIN):
                self._check_trigger(w)
                feat   = self._extract(w, now)
                bscore = self._score(feat, bmodel)
                score  = max(bscore, 0.80)
                results.append(self._report(
                    pid, w, 'RANSOMWARE', score, 'HIGH',
                    f'RANSOM EXT ×{w["ransom_ext_count"]} '
                    f'({w["ransom_ext_seen"]}) ML={bscore:.2f}'))
                del self.windows[pid]; continue

            # L2f: Slow Ransomware — تراكم بطيء لامتدادات أو rename
            slow_ext = w['ransom_ext_count'] + w.get('novel_ext_count', 0)
            has_ext_signal = slow_ext >= 1
            # لازم يكون فيه عمليات على ملفات user + (إما امتداد مشبوه أو rename كثير)
            if (elapsed >= 10.0 and w['fd'] >= 2 and w['had_user_ops']
                    and ((slow_ext >= 2 or (w['rename_patterns'] >= 3 and has_ext_signal))
                         or (slow_ext >= 1 and w['rename_patterns'] >= 2)
                         or (w['rename_patterns'] >= 5 and w['fd_user'] >= 3))):
                # سلوك تشفير بطيء لكن مستمر
                self._check_trigger(w)
                feat   = self._extract(w, now)
                bscore = self._score(feat, bmodel)
                score  = max(bscore, 0.72)
                results.append(self._report(
                    pid, w, 'RANSOMWARE', score, 'HIGH',
                    f'SLOW RANSOM ext×{w["ransom_ext_count"]} '
                    f'novel×{w.get("novel_ext_count", 0)} '
                    f'ren×{w["rename_patterns"]} fd={w["fd"]} '
                    f'fd_u={w["fd_user"]} t={elapsed:.0f}s ML={bscore:.2f}'))
                del self.windows[pid]; continue

            # L2g: Novel/Anomalous Extensions — امتدادات شاذة مش معروفة
            nec = w.get('novel_ext_count', 0)
            if (elapsed >= WINDOW_FAST and nec >= 3 and w['fd'] >= 2
                    and w['had_user_ops']):
                # تحقق إن في امتداد واحد على الأقل تكرر ≥3 مرات
                top_ext = ''
                top_cnt = 0
                for ext, cnt in w.get('novel_ext_map', {}).items():
                    if cnt > top_cnt:
                        top_ext, top_cnt = ext, cnt
                if top_cnt >= 3:
                    self._check_trigger(w)
                    feat   = self._extract(w, now)
                    bscore = self._score(feat, bmodel)
                    score  = max(bscore, 0.78)
                    results.append(self._report(
                        pid, w, 'RANSOMWARE', score, 'HIGH',
                        f'NOVEL EXT "{top_ext}" ×{top_cnt} '
                        f'total_novel={nec} fd={w["fd"]} ML={bscore:.2f}'))
                    del self.windows[pid]; continue

            # L2c: Mass Delete — بس في user data
            delete_rate = w['fd_user'] / max(elapsed, 0.1)
            if (elapsed >= WINDOW_MASS_DEL
                    and w['fd_user'] >= MASS_DELETE_MIN
                    and delete_rate >= DELETE_RATE_MIN):
                self._check_trigger(w)
                feat   = self._extract(w, now)
                bscore = self._score(feat, bmodel)
                score  = max(bscore, 0.75)
                results.append(self._report(
                    pid, w, 'RANSOMWARE', score, 'HIGH',
                    f'MASS DELETE(user) ×{w["fd_user"]} '
                    f'@ {delete_rate:.1f}/s ML={bscore:.2f}'))
                del self.windows[pid]; continue

            # New trigger: vssadmin/bcdedit escalation
            if w['vss_delete_seen'] or w['bcdedit_seen']:
                self._check_trigger(w)
                feat   = self._extract(w, now)
                bscore = self._score(feat, bmodel)
                score  = max(bscore, 0.85)
                sig = 'VSS_DELETE' if w['vss_delete_seen'] else 'BCDEDIT_DISABLE'
                results.append(self._report(
                    pid, w, 'RANSOMWARE', score, 'HIGH',
                    f'{sig} ML={bscore:.2f}'))
                del self.windows[pid]; continue

            # L2e: In-Place Encryption (file time changes in user data)
            if (elapsed >= WINDOW_FAST and w.get('ft_user', 0) >= 10
                    and w['fd'] == 0 and w['fc'] == 0):
                self._check_trigger(w)
                feat   = self._extract(w, now)
                bscore = self._score(feat, bmodel)
                score  = max(bscore, 0.70)
                results.append(self._report(
                    pid, w, 'RANSOMWARE', score, 'HIGH',
                    f'IN-PLACE ENCRYPT ft_user={w.get("ft_user", 0)} ML={bscore:.2f}'))
                del self.windows[pid]; continue

            # L3: ML Full
            if elapsed < WINDOW_ML or w['total_events'] < 3:
                continue

            self._check_trigger(w)
            feat   = self._extract(w, now)
            bscore = self._score(feat, bmodel)

            if bscore >= 0.30:
                if now - self.debug_last.get(pid, 0) >= DEBUG_INTERVAL:
                    print(f"  [DEBUG] {w['name']:22} PID={pid:6} "
                          f"ML={bscore:.3f} | ext×{w['ransom_ext_count']} "
                          f"ren×{w['rename_patterns']} fd_u={w['fd_user']} "
                          f"temp→user={w['temp_to_user_bridge']} "
                          f"vss={w['vss_delete_seen']} bcd={w['bcdedit_seen']} "
                          f"t={elapsed:.0f}s")
                    self.debug_last[pid] = now

            real_signal = self._has_real_signal(w)

            # Adaptive: تعديل العتبات حسب المحرك التكيّفي
            adaptive_mult = self.adaptive.get_threshold_multiplier() if self.adaptive else 1.0
            effective_threshold = THRESHOLD_RANSOM * adaptive_mult
            effective_suspicious = THRESHOLD_SUSPICIOUS * adaptive_mult

            if bscore >= effective_threshold:
                if real_signal:
                    results.append(self._report(
                        pid, w, 'RANSOMWARE', bscore, 'HIGH',
                        f'ML FULL (score={bscore:.3f})'))
                    del self.windows[pid]; continue
                else:
                    results.append(self._report(
                        pid, w, 'suspicious', bscore, 'LOW',
                        f'ML HIGH no behavior (score={bscore:.3f})'))

            elif bscore >= effective_suspicious and real_signal:
                results.append(self._report(
                    pid, w, 'suspicious', bscore, 'MEDIUM',
                    f'ML SUSPICIOUS (score={bscore:.3f})'))

            if elapsed >= WINDOW_RESET:
                self.windows[pid] = self._new(
                    w['name'], w['image'],
                    w['parent_image'], w['parent_pid'], preserve=w)

        return results

    # ══════════════════════════════════════════════════════
    def record_snapshot(self, recorder):
        """وضع التسجيل: snapshot لكل PID متتبَّع، ما نقتل ولا نحذف."""
        now = time.time()

        for pid in list(self.windows.keys()):
            w = self.windows[pid]
            elapsed = now - w['start']
            if elapsed < RECORD_MIN_AGE:
                continue
            if w['total_events'] < 1:
                continue

            # فحص الـ triggers قبل استخراج الـ features
            self._check_trigger(w)

            feat = self._extract(w, now)
            recorder.record(pid, w, feat, now, elapsed)

            # إعادة تعيين periodic مع الاحتفاظ بالإشارات المتراكمة
            if elapsed >= WINDOW_RESET:
                self.windows[pid] = self._new(
                    w['name'], w['image'],
                    w['parent_image'], w['parent_pid'], preserve=w)


# ══════════════════════════════════════════════════════════
class Recorder:
    """يكتب snapshots إلى CSV للتدريب لاحقاً."""

    def __init__(self, path, session_name, label_mode, flush_every=50):
        self.path         = path
        self.session      = session_name
        self.label_mode   = label_mode   # 'benign' | 'ransomware' | 'unlabeled'
        self.buffer       = []
        self.flush_every  = flush_every
        self.n_written    = 0
        self.last_flush   = time.time()
        self._seen_pids   = set()

        # create dir if needed
        d = os.path.dirname(path)
        if d:
            os.makedirs(d, exist_ok=True)

    def _decide_label(self, w):
        if self.label_mode == 'benign':
            return 0, 'session_benign'
        if self.label_mode == 'ransomware':
            if w['malicious_trigger_time'] is None:
                return -1, 'pre_trigger'
            return 1, '+'.join(w['triggers_fired']) or 'post_trigger'
        return -1, 'unlabeled'

    def record(self, pid, w, feat, now, elapsed):
        label, reason = self._decide_label(w)

        row = {
            **feat,
            'label'        : label,
            'label_reason' : reason,
            'session'      : self.session,
            'pid'          : pid,
            'process_name' : w['name'],
            'image_path'   : w['image'][:200] if w['image'] else '',
            'window_age'   : round(elapsed, 2),
            'wall_time'    : dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds'),
        }
        self.buffer.append(row)
        self._seen_pids.add(pid)

        if (len(self.buffer) >= self.flush_every
                or time.time() - self.last_flush >= 30):
            self.flush()

    def flush(self):
        if not self.buffer:
            return
        df = pd.DataFrame(self.buffer)
        # ترتيب الأعمدة: features أولاً ثم metadata
        cols = FEATURE_ORDER + [c for c in df.columns if c not in FEATURE_ORDER]
        df = df[cols]
        header = not os.path.exists(self.path)
        df.to_csv(self.path, mode='a', index=False, header=header)
        self.n_written += len(self.buffer)
        self.buffer = []
        self.last_flush = time.time()

    def status(self):
        return (f"rows_written={self.n_written} "
                f"pending={len(self.buffer)} "
                f"unique_pids={len(self._seen_pids)} "
                f"label_mode={self.label_mode}")


# ══════════════════════════════════════════════════════════
class CowProtector:
    """
    Copy-on-Write Protection — حماية استباقية ضد Zero-Day
    عند أول لمسة لملفات المستخدم من أي بروسس، نسوي نسخة بالذاكرة (RAM)
    ونحط pointer عليها. إذا طلع رانسوموير → نسترجع فوراً.
    إذا طلع آمن → نحذف النسخة ونفرغ الذاكرة.
    """

    MAX_FILE_SIZE  = 10 * 1024 * 1024   # 10MB حد أقصى لملف فردي
    MAX_TOTAL_MB   = 512                 # 512MB حد أقصى للذاكرة الكلية

    def __init__(self, enabled=True, max_mb=512):
        self.enabled    = enabled
        self.max_bytes  = max_mb * 1024 * 1024
        self.used_bytes = 0
        # pointer map: المسار → (محتوى الملف بالذاكرة, mtime, pid, وقت النسخ)
        self.backups    = {}
        self.pid_files  = defaultdict(set)  # pid → مجموعة المسارات المنسوخة
        self.pid_touches = defaultdict(int) # pid → عدد اللمسات في user dirs
        self.scanned    = set()             # (pid, dir) اللي تم مسحها
        self._lock      = threading.Lock()
        self._pool      = ThreadPoolExecutor(max_workers=2,
                                             thread_name_prefix='cow')
        self.stats      = {'backed': 0, 'restored': 0, 'freed': 0,
                           'skipped_size': 0, 'skipped_mem': 0,
                           'skipped_threshold': 0}

    def on_file_event(self, pid, name, filepath, eid):
        """يُستدعى عند أي حدث ملف — يحفظ فقط بعد ما البروسس يلمس ملفات كفاية"""
        if not self.enabled or not filepath:
            return
        if classify_path(filepath) != 'user':
            return

        # عدّ لمسات كل PID في مجلدات user
        self.pid_touches[pid] += 1
        touches = self.pid_touches[pid]

        if touches < COW_ACTIVATE_THRESHOLD:
            # قبل العتبة: نحفظ الملف الملموس فقط (مش المجلد كامل)
            if os.path.isfile(filepath):
                self._pool.submit(self._backup_one, pid, filepath)
            return

        # بعد العتبة: نحفظ المجلد كامل
        directory = os.path.dirname(filepath)
        dir_key = (pid, directory.lower())

        if dir_key not in self.scanned:
            self.scanned.add(dir_key)
            self._pool.submit(self._snapshot_dir, pid, directory)

    def _snapshot_dir(self, pid, directory):
        """مسح كل ملفات المجلد ونسخها للذاكرة (background thread)"""
        try:
            for fname in os.listdir(directory):
                fp = os.path.join(directory, fname)
                if os.path.isfile(fp):
                    self._backup_one(pid, fp)
        except Exception:
            pass

    def _backup_one(self, pid, filepath):
        """نسخة فردية لملف واحد → RAM pointer"""
        fp_key = filepath.lower()

        with self._lock:
            if fp_key in self.backups:
                return  # موجود مسبقاً

        try:
            size = os.path.getsize(filepath)
            if size == 0:
                return
            if size > self.MAX_FILE_SIZE:
                self.stats['skipped_size'] += 1
                return

            with self._lock:
                if self.used_bytes + size > self.max_bytes:
                    self.stats['skipped_mem'] += 1
                    return

            mtime = os.path.getmtime(filepath)
            with open(filepath, 'rb') as f:
                content = f.read()

            with self._lock:
                if fp_key not in self.backups:
                    self.backups[fp_key] = (content, mtime, pid, time.time())
                    self.pid_files[pid].add(fp_key)
                    self.used_bytes += len(content)
                    self.stats['backed'] += 1
        except Exception:
            pass

    def restore_pid(self, pid):
        """رانسوموير مؤكد → نسترجع كل الملفات من الذاكرة"""
        restored = 0
        with self._lock:
            files = list(self.pid_files.get(pid, set()))

        for fp_key in files:
            with self._lock:
                if fp_key not in self.backups:
                    continue
                content, mtime, _, _ = self.backups[fp_key]

            try:
                os.makedirs(os.path.dirname(fp_key), exist_ok=True)
                with open(fp_key, 'wb') as f:
                    f.write(content)
                restored += 1
            except Exception:
                pass

        self.stats['restored'] += restored
        return restored

    def clear_pid(self, pid):
        """بروسس آمن → نحذف النسخ ونفرغ الذاكرة"""
        with self._lock:
            files = self.pid_files.pop(pid, set())
            self.pid_touches.pop(pid, None)
            for fp_key in files:
                if fp_key in self.backups:
                    self.used_bytes -= len(self.backups[fp_key][0])
                    del self.backups[fp_key]
                    self.stats['freed'] += 1

    def periodic_cleanup(self, active_pids, max_age=120):
        """تنظيف دوري — نحذف نسخ البروسيسات اللي خلصت وعمرها أكثر من دقيقتين"""
        now = time.time()
        with self._lock:
            stale = [p for p in self.pid_files
                     if p not in active_pids]
        for pid in stale:
            with self._lock:
                files = self.pid_files.get(pid, set())
                all_old = all(
                    now - self.backups.get(f, (None, None, None, 0))[3] > max_age
                    for f in files if f in self.backups
                )
            if all_old:
                self.clear_pid(pid)

    def status(self):
        with self._lock:
            n = len(self.backups)
            mb = self.used_bytes / (1024 * 1024)
            active = sum(1 for v in self.pid_touches.values()
                         if v >= COW_ACTIVATE_THRESHOLD)
            watching = len(self.pid_touches)
        return (f"COW: {n} files ({mb:.1f}MB) | "
                f"watching={watching} active={active} | "
                f"backed={self.stats['backed']} "
                f"restored={self.stats['restored']} "
                f"freed={self.stats['freed']}")

    def shutdown(self):
        self._pool.shutdown(wait=False)


# ══════════════════════════════════════════════════════════
class StaticScanner:
    """
    Layer 0 — Static PE Analysis
    يفحص كل ملف .exe فور نزوله على الجهاز قبل ما يشتغل.
    يستخرج 7 features من PE header ويمررهم للموديل.
    """

    PE_FEATURES = ['num_sections', 'num_symbols', 'characteristics',
                   'max_section_entropy', 'avg_section_entropy',
                   'num_imported_dlls', 'num_imported_funcs']

    def __init__(self, model_path=None):
        self.model    = None
        self.enabled  = False
        self.scanned  = {}   # {filepath_lower: (score, timestamp)}
        self.flagged  = {}   # {filepath_lower: score}  — الملفات المشبوهة
        self._pool    = ThreadPoolExecutor(max_workers=1,
                                           thread_name_prefix='l0')
        self._lock    = threading.Lock()
        self.stats    = {'scanned': 0, 'flagged': 0, 'blocked': 0, 'errors': 0}

        if model_path and os.path.exists(model_path):
            try:
                import warnings
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    self.model = joblib.load(model_path)
                self.enabled = True
                print(f"  [+] L0 Static: {type(self.model).__name__} loaded")
                if hasattr(self.model, 'n_features_in_'):
                    print(f"  [+] L0 Features: {self.model.n_features_in_}")
            except Exception as e:
                print(f"  [!] L0 load failed: {e}")

    def on_file_create(self, filepath, pid, name):
        """يُستدعى عند إنشاء ملف — إذا .exe نفحصه بـ background thread"""
        if not self.enabled or not filepath:
            return
        if not filepath.lower().endswith(('.exe', '.scr', '.com')):
            return

        fp_key = filepath.lower()
        with self._lock:
            if fp_key in self.scanned:
                return  # تم فحصه مسبقاً

        self._pool.submit(self._scan_pe, filepath, pid, name)

    def _extract_features(self, filepath):
        """استخراج 7 features من PE header"""
        pe = pefile.PE(filepath, fast_load=False)
        try:
            num_sections = pe.FILE_HEADER.NumberOfSections
            num_symbols  = pe.FILE_HEADER.NumberOfSymbols
            chars        = pe.FILE_HEADER.Characteristics

            entropies = [s.get_entropy() for s in pe.sections]
            max_ent = max(entropies) if entropies else 0.0
            avg_ent = (sum(entropies) / len(entropies)) if entropies else 0.0

            n_dlls  = 0
            n_funcs = 0
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                n_dlls  = len(pe.DIRECTORY_ENTRY_IMPORT)
                n_funcs = sum(len(e.imports) for e in pe.DIRECTORY_ENTRY_IMPORT)

            return {
                'num_sections':        num_sections,
                'num_symbols':         num_symbols,
                'characteristics':     chars,
                'max_section_entropy': round(max_ent, 4),
                'avg_section_entropy': round(avg_ent, 4),
                'num_imported_dlls':   n_dlls,
                'num_imported_funcs':  n_funcs,
            }
        finally:
            pe.close()

    def _scan_pe(self, filepath, pid, name):
        """فحص PE واحد (background thread)"""
        fp_key = filepath.lower()
        try:
            feat = self._extract_features(filepath)
            values = [feat[k] for k in self.PE_FEATURES]
            df = pd.DataFrame([values], columns=self.PE_FEATURES)

            import warnings
            with warnings.catch_warnings():
                warnings.simplefilter('ignore')
                score = float(self.model.predict_proba(df)[0][1])

            with self._lock:
                self.scanned[fp_key] = (score, time.time())
                self.stats['scanned'] += 1

                if score >= L0_THRESHOLD:
                    self.flagged[fp_key] = score
                    self.stats['flagged'] += 1

            fname = os.path.basename(filepath)
            if score >= L0_BLOCK_THRESHOLD:
                self.stats['blocked'] += 1
                print(f"\n  {'⚠'*27}")
                print(f"  [L0] ☠️  MALICIOUS EXE DETECTED!")
                print(f"     File  : {fname}")
                print(f"     Score : {score:.3f}")
                print(f"     Path  : {filepath}")
                print(f"     PID   : {pid} ({name})")
                print(f"  {'⚠'*27}\n")
            elif score >= L0_THRESHOLD:
                print(f"  [L0] ⚠️  Suspicious EXE: {fname} "
                      f"(score={score:.3f}) PID={pid}")
            elif score >= 0.4:
                print(f"  [L0] 🔍 Low-risk EXE: {fname} "
                      f"(score={score:.3f})")

        except Exception as e:
            self.stats['errors'] += 1

    def is_flagged(self, filepath):
        """هل الملف مشبوه ساكنياً؟"""
        if not filepath:
            return False, 0.0
        with self._lock:
            score = self.flagged.get(filepath.lower(), 0.0)
        return score >= L0_THRESHOLD, score

    def status(self):
        with self._lock:
            return (f"L0: scanned={self.stats['scanned']} "
                    f"flagged={self.stats['flagged']} "
                    f"blocked={self.stats['blocked']}")

    def shutdown(self):
        self._pool.shutdown(wait=False)


# ══════════════════════════════════════════════════════════
class AdaptiveEngine:
    """
    Adaptive Engine — محرك تكيّفي لكل جهاز
    يبني baseline سلوكي خاص بالجهاز ويعدّل العتبات ديناميكياً.
    يحفظ البروفايل بملف JSON يبقى بعد إعادة التشغيل.
    """

    def __init__(self, profile_dir=None):
        self.profile_dir = profile_dir or ADAPTIVE_PROFILE_DIR
        os.makedirs(self.profile_dir, exist_ok=True)

        # معرّف فريد للجهاز
        self.machine_id = self._get_machine_id()
        self.profile_path = os.path.join(
            self.profile_dir, f'adaptive_{self.machine_id}.json')

        # الحالة الحالية — rolling windows
        self.current = {
            'fc_per_min': [],    # معدل إنشاء ملفات (آخر 10 دقائق)
            'fd_per_min': [],    # معدل حذف ملفات
            'proc_per_min': [],  # معدل إنشاء بروسيسات
            'seen_processes': set(),   # أسماء البروسيسات المعروفة
            'seen_extensions': set(),  # الامتدادات المعتادة
            'hourly_activity': defaultdict(int),  # نشاط حسب الساعة
        }

        # البروفايل المحفوظ (baseline)
        self.baseline = self._load_profile()
        self.last_save = time.time()
        self.last_update = time.time()
        self._minute_counts = {'fc': 0, 'fd': 0, 'pc': 0}

        if self.baseline:
            print(f"  [+] Adaptive: Profile loaded ({self.machine_id[:8]}...)")
            print(f"      Baseline: fc={self.baseline.get('avg_fc_per_min', '?'):.1f}/min "
                  f"fd={self.baseline.get('avg_fd_per_min', '?'):.1f}/min "
                  f"known_procs={len(self.baseline.get('known_processes', []))}")
        else:
            print(f"  [+] Adaptive: New device — building baseline ({self.machine_id[:8]}...)")

    def _get_machine_id(self):
        """معرّف فريد للجهاز"""
        try:
            name = os.environ.get('COMPUTERNAME', 'unknown')
            user = os.environ.get('USERNAME', 'unknown')
            raw = f"{name}-{user}-ransomshield"
            return hashlib.sha256(raw.encode()).hexdigest()[:16]
        except Exception:
            return 'default'

    def _load_profile(self):
        """تحميل البروفايل من الديسك"""
        try:
            if os.path.exists(self.profile_path):
                with open(self.profile_path, 'r') as f:
                    return json.load(f)
        except Exception:
            pass
        return None

    def _save_profile(self):
        """حفظ البروفايل للديسك"""
        try:
            profile = {
                'machine_id': self.machine_id,
                'last_update': dt.datetime.now().isoformat(),
                'avg_fc_per_min': self._rolling_avg(self.current['fc_per_min']),
                'avg_fd_per_min': self._rolling_avg(self.current['fd_per_min']),
                'avg_proc_per_min': self._rolling_avg(self.current['proc_per_min']),
                'std_fc_per_min': self._rolling_std(self.current['fc_per_min']),
                'std_fd_per_min': self._rolling_std(self.current['fd_per_min']),
                'known_processes': list(self.current['seen_processes']),
                'known_extensions': list(self.current['seen_extensions']),
                'hourly_activity': dict(self.current['hourly_activity']),
                'total_sessions': (self.baseline or {}).get('total_sessions', 0) + 1,
            }
            with open(self.profile_path, 'w') as f:
                json.dump(profile, f, indent=2)
            self.baseline = profile
        except Exception:
            pass

    @staticmethod
    def _rolling_avg(lst):
        return round(sum(lst) / max(len(lst), 1), 2)

    @staticmethod
    def _rolling_std(lst):
        if len(lst) < 2:
            return 0.0
        avg = sum(lst) / len(lst)
        var = sum((x - avg) ** 2 for x in lst) / len(lst)
        return round(math.sqrt(var), 2)

    def on_event(self, eid, name, target):
        """يُستدعى مع كل حدث Sysmon"""
        hour = str(dt.datetime.now().hour)
        self.current['hourly_activity'][hour] += 1

        if name:
            self.current['seen_processes'].add(name.lower())

        if target:
            ext = os.path.splitext(target)[1].lower()
            if ext:
                self.current['seen_extensions'].add(ext)

        if eid == 1:
            self._minute_counts['pc'] += 1
        elif eid == 11:
            self._minute_counts['fc'] += 1
        elif eid in (23, 26):
            self._minute_counts['fd'] += 1

    def update(self):
        """تحديث دوري — يُستدعى كل 60 ثانية"""
        now = time.time()
        elapsed = now - self.last_update
        if elapsed < 55:
            return

        # حساب المعدلات بالدقيقة
        factor = 60.0 / max(elapsed, 1)
        self.current['fc_per_min'].append(
            round(self._minute_counts['fc'] * factor, 1))
        self.current['fd_per_min'].append(
            round(self._minute_counts['fd'] * factor, 1))
        self.current['proc_per_min'].append(
            round(self._minute_counts['pc'] * factor, 1))

        # الاحتفاظ بآخر 30 عينة فقط (30 دقيقة)
        for k in ('fc_per_min', 'fd_per_min', 'proc_per_min'):
            self.current[k] = self.current[k][-30:]

        self._minute_counts = {'fc': 0, 'fd': 0, 'pc': 0}
        self.last_update = now

        # حفظ البروفايل كل 5 دقائق
        if now - self.last_save >= 300:
            self._save_profile()
            self.last_save = now

    def get_threshold_multiplier(self):
        """
        يرجع مضاعف العتبة بناءً على الانحراف عن السلوك الطبيعي.
        < 1.0 = خفّض العتبات (سلوك غير طبيعي — كشف أسرع)
        = 1.0 = عتبات عادية
        > 1.0 = ارفع العتبات (سلوك طبيعي جداً — تجنب false positives)
        """
        if not self.baseline or len(self.current['fc_per_min']) < 2:
            return 1.0  # ما عنا بيانات كافية بعد

        multiplier = 1.0

        # 1. فحص معدل إنشاء الملفات
        curr_fc = self._rolling_avg(self.current['fc_per_min'][-5:])
        base_fc = self.baseline.get('avg_fc_per_min', 5)
        std_fc  = self.baseline.get('std_fc_per_min', 2)
        if std_fc > 0 and curr_fc > base_fc + 3 * std_fc:
            multiplier *= 0.7  # خفّض العتبة — نشاط غير طبيعي

        # 2. فحص معدل الحذف
        curr_fd = self._rolling_avg(self.current['fd_per_min'][-5:])
        base_fd = self.baseline.get('avg_fd_per_min', 2)
        std_fd  = self.baseline.get('std_fd_per_min', 1)
        if std_fd > 0 and curr_fd > base_fd + 3 * std_fd:
            multiplier *= 0.7

        # 3. ساعة غير معتادة
        hour = str(dt.datetime.now().hour)
        hourly = self.baseline.get('hourly_activity', {})
        if hourly:
            avg_hourly = sum(hourly.values()) / max(len(hourly), 1)
            this_hour = hourly.get(hour, 0)
            if this_hour < avg_hourly * 0.1:  # ساعة نادرة
                multiplier *= 0.8

        # 4. بروسس غير معروف
        # (يتم فحصه في evaluate عبر is_new_process)

        return max(multiplier, 0.5)  # حد أدنى 0.5

    def is_new_process(self, name):
        """هل البروسس ما شفناه قبل على هذا الجهاز؟"""
        if not self.baseline:
            return False
        known = set(self.baseline.get('known_processes', []))
        return name.lower() not in known

    def status(self):
        n = len(self.current['fc_per_min'])
        mult = self.get_threshold_multiplier()
        fc = self._rolling_avg(self.current['fc_per_min'][-5:]) if n else 0
        fd = self._rolling_avg(self.current['fd_per_min'][-5:]) if n else 0
        return (f"Adaptive: fc={fc:.0f}/min fd={fd:.0f}/min "
                f"mult={mult:.2f} procs={len(self.current['seen_processes'])}")

    def save_final(self):
        """حفظ أخير قبل الإغلاق"""
        self._save_profile()


# ══════════════════════════════════════════════════════════
def load_model(path):
    try:
        raw = joblib.load(path)
        print(f"  [+] PKL loaded: {type(raw).__name__}")
        if isinstance(raw, dict):
            clf     = raw.get('model') or raw.get('classifier') or raw.get('clf') or raw.get('l2_model')
            scaler  = raw.get('scaler') or raw.get('l2_scaler')
            feat_ls = raw.get('features') or raw.get('l2_features')
            print(f"  [+] Classifier : {type(clf).__name__}")
            print(f"  [+] Scaler     : {type(scaler).__name__ if scaler else 'None'}")
            print(f"  [+] Features   : {len(feat_ls) if feat_ls else '?'}")
            # Feature compatibility check
            if hasattr(clf, 'n_features_in_'):
                expected = clf.n_features_in_
                actual = len(feat_ls) if feat_ls else len(FEATURE_ORDER)
                if expected != actual:
                    print(f"  [!] WARNING: Model expects {expected} features "
                          f"but pipeline has {actual}!")
            return {'clf': clf, 'scaler': scaler, 'features': feat_ls}
        # Raw model (not dict)
        if hasattr(raw, 'n_features_in_'):
            n = raw.n_features_in_
            if n != len(FEATURE_ORDER):
                print(f"  [!] WARNING: Model expects {n} features "
                      f"but FEATURE_ORDER has {len(FEATURE_ORDER)}!")
        return {'clf': raw, 'scaler': None, 'features': None}
    except Exception as e:
        print(f"  [!] ML load failed: {e}")
        return None


def kill_process(pid, name, enabled):
    if not enabled:
        print(f"  [LOCKED] Would kill: {name} (PID {pid})"); return
    try:
        proc = psutil.Process(int(pid))
        ch   = proc.children(recursive=True)
        for c in ch:
            try: c.terminate()
            except Exception: pass
        proc.terminate()
        print(f"  [X] KILLED: {name} (PID {pid}) + {len(ch)} children")
    except psutil.NoSuchProcess:
        print(f"  [X] Already exited: PID {pid}")
    except Exception as ex:
        print(f"  [!] Kill failed: {ex}")


# ══════════════════════════════════════════════════════════
def parse_args():
    p = argparse.ArgumentParser(
        description="RansomShield Layer 2 v22 — production + recording")
    p.add_argument('--record-mode', metavar='CSV_PATH', default=None,
                   help='Path to output CSV. Activates recording.')
    p.add_argument('--label', choices=['benign', 'ransomware', 'unlabeled'],
                   default='unlabeled',
                   help='Label policy for recorded rows.')
    p.add_argument('--session', default=None,
                   help='Session name (group identifier in training).')
    p.add_argument('--duration', type=float, default=0,
                   help='Auto-stop after N seconds (0 = run until Ctrl-C).')
    p.add_argument('--unlock-kill', action='store_true',
                   help='Production: actually terminate detected processes.')
    p.add_argument('--verbose', action='store_true')
    p.add_argument('--no-honeypot', action='store_true')
    p.add_argument('--model', default='ransomshield_complete.pkl',
                   help='Path to trained model .pkl (production mode).')
    p.add_argument('--l0-model', default='ransomware_rf_model.pkl',
                   help='Path to Layer 0 static PE analysis model.')
    return p.parse_args()


def main():
    args = parse_args()

    if not WINDOWS_AVAILABLE:
        print("[!] This agent requires Windows + win32evtlog + psutil + joblib.")
        print("[!] Run this on your Windows VM, not on Linux/Mac.")
        sys.exit(1)

    AGENT_START_UTC = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)
    recording = args.record_mode is not None

    # Auto-generate session name if missing
    if recording and not args.session:
        args.session = (f"{args.label}_"
                        f"{AGENT_START_UTC.strftime('%Y%m%d_%H%M%S')}")

    print(f"""
{'='*62}
  RansomShield Layer 2 v22 — {'RECORDING' if recording else 'PRODUCTION'}
{'='*62}
  Started at  : {AGENT_START_UTC.strftime('%Y-%m-%d %H:%M:%S')} UTC
  Mode        : {'RECORD (ml scoring disabled, no kills)' if recording else 'DETECT'}
  {'Output      : ' + args.record_mode if recording else
   'Kill Mode   : ' + ('ENABLED' if args.unlock_kill else 'LOCKED')}
  {'Label       : ' + args.label + '  Session: ' + args.session if recording else
   'Model       : ' + args.model}
  Honeypot    : {'Disabled' if args.no_honeypot else 'Enabled'}
  Duration    : {'run until Ctrl-C' if args.duration == 0 else f'{args.duration}s'}
{'='*62}""")

    # في وضع التسجيل ما نحمّل المودل (المودل القديم ما بيتوافق مع features الجديدة)
    bmodel = None
    l0 = None
    adaptive = None
    if not recording:
        sd = os.path.dirname(os.path.abspath(__file__))
        bmodel = load_model(os.path.join(sd, args.model))
        l0 = StaticScanner(os.path.join(sd, args.l0_model))
        adaptive = AdaptiveEngine()

    # Setup logging to file
    log_dir = os.path.join(os.path.expanduser('~'), '.ransomshield')
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, 'ransomshield.log')
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s',
        handlers=[
            logging.FileHandler(log_file, encoding='utf-8'),
            logging.StreamHandler(sys.stdout)
        ]
    )
    logger = logging.getLogger('RansomShield')
    logger.info(f"RansomShield v22 started — {'RECORDING' if recording else 'PRODUCTION'}")

    # في وضع تسجيل benign مفيش honeypot ينزلو (نبيها usage نظيف)
    hp_on = not args.no_honeypot and not (recording and args.label == 'benign')
    hp    = Honeypot(enabled=hp_on)
    eng   = Engine(honeypot=hp, adaptive=adaptive)
    cow   = CowProtector(enabled=not recording)
    guard = SysmonGuard()
    seen  = set()
    last_cow_clean = time.time()
    last_adaptive  = time.time()

    recorder = None
    if recording:
        recorder = Recorder(args.record_mode, args.session, args.label)
        print(f"  [REC] writing to: {args.record_mode}")

    start_ts = time.time()
    last_rec_flush = time.time()
    last_snapshot  = time.time()
    last_status    = time.time()

    print(f"\n  [>] Monitoring started...\n{'='*62}\n")

    try:
        import win32event

        # 1. إنشاء كائن انتظار (Event) لالتقاط الأحداث الجديدة بدون استهلاك الموارد
        h_evt = win32event.CreateEvent(None, 0, 0, None)

        # 2. فتح اشتراك بـ Sysmon للأحداث المستقبلية فقط
        handle = win32evtlog.EvtSubscribe(
            LOG_PATH, 
            win32evtlog.EvtSubscribeToFutureEvents, 
            SignalEvent=h_evt, 
            Query=QUERY
        )

        while True:
            # Duration check
            if args.duration > 0 and time.time() - start_ts >= args.duration:
                print(f"\n  [i] Duration reached. Stopping.")
                break

            guard.check()

            # 3. انتظار حدث جديد بحد أقصى 500 ملي ثانية (لتوفير الـ CPU)
            win32event.WaitForSingleObject(h_evt, 500)
            
            events = []
            try:
                # 4. جلب دفعة من الأحداث الجديدة (حتى 200 حدث)
                events = win32evtlog.EvtNext(handle, 200)
            except Exception:
                pass

            for event in (events or []):
                try:
                    xstr = win32evtlog.EvtRender(
                        event, win32evtlog.EvtRenderEventXml)
                    root = ET.fromstring(xstr)
                    eid  = int(root.find("./e:System/e:EventID", NS).text)
                    et   = root.find("./e:System/e:TimeCreated", NS
                                     ).attrib.get("SystemTime", "?")

                    event_dt = parse_event_time(et)
                    if event_dt and event_dt < AGENT_START_UTC:
                        continue

                    data = {d.attrib.get("Name"): (d.text or "")
                            for d in root.findall(".//e:Data", NS)}

                    pid = data.get("ProcessId")
                    if not pid:
                        continue

                    ek = (et, eid, pid)
                    if ek in seen:
                        continue
                    seen.add(ek)
                    if len(seen) > 200_000:
                        # Partial eviction: حذف النص الأقدم بدل clear() كامل
                        seen_list = sorted(seen)
                        seen = set(seen_list[100_000:])

                    nm = data.get("Image", "").split("\\")[-1].lower()
                    if nm in IGNORE:
                        continue

                    if args.verbose:
                        if eid == 1:
                            print(f"  [+] New Process: {nm} (PID: {pid})")
                        elif eid == 11:
                            tf = data.get("TargetFilename", "")
                            print(f"  [F] FileCreate: {nm} PID={pid} -> {tf[-60:]}")
                        elif eid in (23, 26):
                            tf = data.get("TargetFilename", "")
                            print(f"  [D] FileDelete: {nm} PID={pid} -> {tf[-60:]}")

                    target = data.get("TargetFilename",
                                      data.get("TargetObject", ""))

                    eng.add(
                        pid, nm,
                        data.get("Image", ""),
                        eid, target,
                        data.get("ParentImage", ""),
                        data.get("ParentProcessId", ""),
                        data.get("CommandLine", ""),
                    )

                    # COW: نسخ استباقي للملفات عند أول لمسة
                    if eid in (11, 23, 26) and cow.enabled:
                        cow.on_file_event(pid, nm, target, eid)

                    # L0: فحص ساكن لملفات .exe الجديدة
                    if eid == 11 and l0 and l0.enabled:
                        l0.on_file_create(target, pid, nm)

                    # Adaptive: تسجيل الحدث
                    if adaptive:
                        adaptive.on_event(eid, nm, target)

                    # COW: تنظيف عند إنهاء بروسس آمن (EID 5)
                    if eid == 5 and pid not in eng.killed:
                        cow.clear_pid(pid)
                except Exception as ev_err:
                    logging.debug(f"Event parse error: {ev_err}")
                    continue

            now = time.time()

            # طباعة حالة التتبع كل 10 ثواني
            if args.verbose and now - last_status >= 10:
                tracked = len(eng.windows)
                if tracked > 0:
                    print(f"  [STATUS] Tracking {tracked} PIDs | "
                          f"Events in seen-set: {len(seen)}")
                    print(f"  [STATUS] {cow.status()}")
                    if l0:
                        print(f"  [STATUS] {l0.status()}")
                    if adaptive:
                        print(f"  [STATUS] {adaptive.status()}")
                    for tpid, tw in list(eng.windows.items())[:5]:
                        print(f"    PID={tpid} {tw['name']:20} "
                              f"fc={tw['fc']} fd={tw['fd']} "
                              f"ren={tw['rename_patterns']} "
                              f"rext={tw['ransom_ext_count']} "
                              f"total={tw['total_events']}")
                last_status = now

            if recording:
                # Snapshot دوري
                if now - last_snapshot >= RECORD_INTERVAL:
                    eng.record_snapshot(recorder)
                    last_snapshot = now

                if now - last_rec_flush >= 30:
                    recorder.flush()
                    last_rec_flush = now

            else:
                # Production evaluation
                for r in eng.evaluate(bmodel):
                    ts = datetime.now().strftime("%H:%M:%S")
                    if r['decision'] == "RANSOMWARE":
                        # COW: استرجاع فوري للملفات من الذاكرة
                        n_restored = cow.restore_pid(r['pid'])

                        print(f"\n  {'!'*54}")
                        print(f"  [{ts}]  RANSOMWARE  [{r['confidence']}]")
                        print(f"     Process : {r['name']} (PID {r['pid']})")
                        print(f"     Score   : {r['score']:.3f}")
                        print(f"     Trigger : {r['reason']}")
                        if n_restored:
                            print(f"     COW     : ✅ {n_restored} files RESTORED from RAM!")
                        print(f"  {'!'*54}\n")
                        kill_process(r['pid'], r['name'], args.unlock_kill)
                    elif r['decision'] == "suspicious" and args.verbose:
                        print(f"  [{ts}]  SUSPICIOUS [{r['confidence']}] : "
                              f"{r['name']} (PID {r['pid']}) — {r['reason']}")

            # Adaptive: تحديث دوري
            if adaptive and now - last_adaptive >= ADAPTIVE_UPDATE_SEC:
                adaptive.update()
                last_adaptive = now

            # COW: تنظيف دوري للنسخ القديمة (كل 30 ثانية)
            if now - last_cow_clean >= 30:
                cow.periodic_cleanup(set(eng.windows.keys()))
                last_cow_clean = now

            time.sleep(POLL_MS)

    except KeyboardInterrupt:
        print(f"\n{'='*62}\n  Stopped by user.")
    except Exception as ex:
        print(f"\n  [FATAL] {ex}")
    finally:
        if recorder:
            # Snapshot أخير لكل PID قبل الإغلاق
            eng.record_snapshot(recorder)
            recorder.flush()
            print(f"\n  [REC] Final: {recorder.status()}")
            print(f"  [REC] CSV: {args.record_mode}")
        if not recording:
            print(f"  Incidents : {len(eng.incidents)}")
            print(f"  Killed    : {eng.killed or 'none'}")
            print(f"  {cow.status()}")
            if l0:
                print(f"  {l0.status()}")
                l0.shutdown()
            if adaptive:
                print(f"  {adaptive.status()}")
                adaptive.save_final()
            cow.shutdown()
        print('='*62)
        if hp.enabled:
            hp.cleanup()


if __name__ == "__main__":
    main()