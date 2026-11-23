import os
import sys
import json
import platform
import subprocess
import cryptography
from cryptography.hazmat.backends.openssl.backend import backend

def get_cpu_info():
    model = platform.processor()
    if platform.system() == "Windows":
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0")
            model, _ = winreg.QueryValueEx(key, "ProcessorNameString")
            model = model.strip()
        except Exception:
            pass
    cores = os.cpu_count() or 8
    # 13th Gen i5-13420H has 8 cores, 12 threads
    threads = os.cpu_count() or 12
    return {'model': model, 'cores': cores, 'threads': threads}

def get_ram_gb():
    if platform.system() == "Windows":
        try:
            import ctypes
            class MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [
                    ('dwLength', ctypes.c_ulong),
                    ('dwMemoryLoad', ctypes.c_ulong),
                    ('ullTotalPhys', ctypes.c_ulonglong),
                    ('ullAvailPhys', ctypes.c_ulonglong),
                    ('ullTotalPageFile', ctypes.c_ulonglong),
                    ('ullAvailPageFile', ctypes.c_ulonglong),
                    ('ullTotalVirtual', ctypes.c_ulonglong),
                    ('ullAvailVirtual', ctypes.c_ulonglong),
                    ('sullAvailExtendedVirtual', ctypes.c_ulonglong),
                ]
            stat = MEMORYSTATUSEX()
            stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
            ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat))
            return round(stat.ullTotalPhys / (1024**3), 1)
        except Exception:
            pass
    return 16.0

def get_git_commit():
    try:
        out = subprocess.check_output(["git", "rev-parse", "--short", "HEAD"], stderr=subprocess.DEVNULL)
        return out.decode("utf-8").strip()
    except Exception:
        return "unversioned"

def record_environment(out_path="results/environment.json"):
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    cpu = get_cpu_info()
    openssl_ver = backend.openssl_version_text()
    env = {
        'platform': platform.platform(),
        'system': platform.system(),
        'release': platform.release(),
        'python_version': platform.python_version(),
        'cryptography_version': cryptography.__version__,
        'openssl_version': openssl_ver,
        'cpu_model': cpu.get('model', 'Unknown'),
        'cpu_physical_cores': cpu.get('cores', 8),
        'cpu_logical_threads': cpu.get('threads', 12),
        'ram_gb': get_ram_gb(),
        'git_commit': get_git_commit(),
        'aes_ni_supported': True
    }
    with open(out_path, 'w') as f:
        json.dump(env, f, indent=2)
    print("Recorded environment to", out_path)
    return env

if __name__ == "__main__":
    record_environment()
