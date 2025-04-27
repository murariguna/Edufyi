import psutil
import ctypes
import win32api
import win32con
import win32gui
import time

SAFE_PROCESSES = [
    "svchost.exe", "explorer.exe", "MsMpEng.exe", "chrome.exe", "Code.exe",
    "OneDrive.exe", "powershell.exe", "RuntimeBroker.exe", "SearchHost.exe",
    "dllhost.exe", "SnippingTool.exe", "TextInputHost.exe", "python.exe",
    "SystemSettings.exe", "conhost.exe", "ctfmon.exe"
]

SUSPICIOUS_KEYWORDS = ["keylog", "spy", "hook", "stealth", "capture"]

def has_keyboard_hook():
    try:
        for i in range(0, 255):
            if win32api.GetAsyncKeyState(i):
                return True
        return False
    except:
        return False

def is_hidden(pid):
    try:
        hwnd = win32gui.FindWindow(None, psutil.Process(pid).name())
        return hwnd == 0
    except:
        return False

def detect_keyloggers():
    print("[*] Scanning for potential keyloggers...")
    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            pname = proc.info['name'] or ""
            if pname in SAFE_PROCESSES:
                continue

            pid = proc.info['pid']
            exe = proc.info['exe'] or ""

            suspicious = False

            for keyword in SUSPICIOUS_KEYWORDS:
                if keyword in pname.lower() or keyword in exe.lower():
                    suspicious = True

            if is_hidden(pid):
                print(f"[!] Hidden process: {pname} (PID: {pid})")

            if suspicious:
                print(f"[!] Suspicious process name: {pname} (PID: {pid})")

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    if has_keyboard_hook():
        print("[!] WARNING: A global keyboard hook is active! This could be a keylogger.")

print("== Keylogger Detection System (Improved) ==")
while True:
    detect_keyloggers()
    print("[*] Scan complete. Sleeping for 10 seconds...")
    time.sleep(10)
