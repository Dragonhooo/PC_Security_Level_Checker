import ctypes
import ctypes.wintypes
import tkinter as tk
from tkinter import messagebox, ttk
from datetime import datetime, timedelta
import subprocess
import re
import os
import winreg
import win32com.client
import webbrowser

def check_password_set():
    try:
        netapi32 = ctypes.windll.netapi32

        class USER_INFO_1(ctypes.Structure):
            _fields_ = [
                ("usri1_name", ctypes.c_wchar_p),
                ("usri1_password", ctypes.c_wchar_p),
                ("usri1_password_age", ctypes.c_ulong),
                ("usri1_priv", ctypes.c_ulong),
                ("usri1_home_dir", ctypes.c_wchar_p),
                ("usri1_comment", ctypes.c_wchar_p),
                ("usri1_flags", ctypes.c_ulong),
                ("usri1_script_path", ctypes.c_wchar_p)
            ]

        buffer = ctypes.create_unicode_buffer(257)
        ctypes.windll.advapi32.GetUserNameW(buffer, ctypes.byref(ctypes.wintypes.DWORD(257)))
        username = buffer.value

        bufptr = ctypes.POINTER(USER_INFO_1)()
        res = netapi32.NetUserGetInfo(None, ctypes.c_wchar_p(username), 1, ctypes.byref(bufptr))

        if res == 0:
            user_info = bufptr.contents
            password_is_set = not bool(user_info.usri1_flags & 0x0020)
            netapi32.NetApiBufferFree(bufptr)
            return password_is_set
        else:
            return False
    except Exception as e:
        return False

def check_password_age():
    try:
        if not check_password_set():
            return 0

        netapi32 = ctypes.windll.netapi32

        class USER_INFO_1(ctypes.Structure):
            _fields_ = [
                ("usri1_name", ctypes.c_wchar_p),
                ("usri1_password", ctypes.c_wchar_p),
                ("usri1_password_age", ctypes.c_ulong),
                ("usri1_priv", ctypes.c_ulong),
                ("usri1_home_dir", ctypes.c_wchar_p),
                ("usri1_comment", ctypes.c_wchar_p),
                ("usri1_flags", ctypes.c_ulong),
                ("usri1_script_path", ctypes.c_wchar_p)
            ]

        buffer = ctypes.create_unicode_buffer(257)
        ctypes.windll.advapi32.GetUserNameW(buffer, ctypes.byref(ctypes.wintypes.DWORD(257)))
        username = buffer.value

        bufptr = ctypes.POINTER(USER_INFO_1)()
        res = netapi32.NetUserGetInfo(None, ctypes.c_wchar_p(username), 1, ctypes.byref(bufptr))

        if res == 0:
            user_info = bufptr.contents
            password_last_set = user_info.usri1_password_age
            netapi32.NetApiBufferFree(bufptr)

            password_last_set_days = password_last_set // (60 * 60 * 24)
            password_last_set_date = datetime.now() - timedelta(days=password_last_set_days)
            three_months_ago = datetime.now() - timedelta(days=90)

            if password_last_set_date >= three_months_ago:
                return 9
            else:
                return 0
        else:
            return 0
    except Exception as e:
        return 0

def check_screensaver_set():
    try:
        key = reg.OpenKey(reg.HKEY_CURRENT_USER, r"Control Panel\Desktop", 0, reg.KEY_READ)
        screensaver_active, _ = reg.QueryValueEx(key, "ScreenSaveActive")
        screensaver_exe, _ = reg.QueryValueEx(key, "SCRNSAVE.EXE")
        reg.CloseKey(key)

        if screensaver_active == "1" and screensaver_exe:
            return 9
        else:
            return 0
    except Exception as e:
        return 0

def check_no_shared_folders():
    try:
        # Run the command to list shared folders
        result = subprocess.run(['net', 'share'], stdout=subprocess.PIPE, text=True)
        output = result.stdout

        # Print the entire output for debugging purposes
        print("net share output:\n", output)

        # Split output into lines
        lines = output.splitlines()

        # Define default shares
        default_shares = {"ADMIN$", "C$", "IPC$", "D$", "E$", "F$", "G$", "H$", "I$", "J$", "K$", "L$", "M$", "N$", "O$", "P$", "Q$", "R$", "S$", "T$", "U$", "V$", "W$", "X$", "Y$", "Z$"}
        user_shares = []

        # Use a regex pattern to match valid share names
        share_pattern = re.compile(r'^[A-Za-z0-9$_.-]+$')

        # Skip the first few lines that contain the header and separator
        for line in lines[4:]:  # Start checking from the 5th line
            parts = line.split()
            if len(parts) > 0:
                share_name = parts[0]
                print("Found share:", share_name)  # Print each share name for debugging
                # Check if the share name is valid and not in default shares
                if share_pattern.match(share_name) and share_name not in default_shares and not share_name.startswith('---'):
                    user_shares.append(share_name)
                    print("User share detected:", share_name)  # Print detected user share

        # Print detected user shares for debugging
        print("User shares:", user_shares)

        # If there are no user-defined shared folders, return 9 points
        if len(user_shares) == 0:
            return 9
        else:
            return 0
    except Exception as e:
        print("Error:", str(e))  # Print the exception for debugging
        return 0
    
def check_os_updated():
    try:
        command = "powershell.exe Get-WindowsUpdateLog"
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True)
        output = result.stdout
        error_output = result.stderr

        if "No updates are available" in output or "No updates" in output:
            return 9
        else:
            return 0

    except Exception as e:
        return 0

def check_antivirus_installed():
    alyac_path = "C:\\Program Files\\ESTsoft\\ALYac\\AYLaunch.exe"
    v3_path = "C:\\Program Files\\AhnLab\\V3Lite\\V3Lite.exe"
    if os.path.exists(alyac_path) or os.path.exists(v3_path):
        return 9
    else:
        return 0

def check_antivirus_updated():
    alyac_path = "C:\\Program Files\\ESTsoft\\ALYac\\AYLaunch.exe"
    v3_path = "C:\\Program Files\\AhnLab\\V3Lite\\V3Lite.exe"

    if os.path.exists(alyac_path):
        update_folder = "C:\\ProgramData\\ESTsoft\\ALYac\\update"
        if os.path.exists(update_folder):
            latest_modification = max(
                os.path.getmtime(os.path.join(update_folder, f))
                for f in os.listdir(update_folder)
                if os.path.isfile(os.path.join(update_folder, f))
            )
            last_updated_date = datetime.fromtimestamp(latest_modification).date()
            today_date = datetime.now().date()
            return 9 if last_updated_date == today_date else 0
        return 0
    elif os.path.exists(v3_path):
        try:
            result = subprocess.run('powershell "Get-WmiObject -Query \'Select * from Win32_Product WHERE Name LIKE \'V3Lite\'\'"',
                                    capture_output=True, text=True, shell=True)
            if result.returncode == 0 and 'V3Lite' in result.stdout:
                return 9
        except Exception as e:
            return 0
    return 0

def check_usb_autorun_disabled():
    try:
        reg_paths = [
            r'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer',
            r'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer',
        ]
        
        for reg_path in reg_paths:
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path) as key:
                    value, regtype = winreg.QueryValueEx(key, 'NoDriveTypeAutoRun')
                    if value == 0xFF:
                        return 9
            except FileNotFoundError:
                pass
            
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path) as key:
                    value, regtype = winreg.QueryValueEx(key, 'NoDriveTypeAutoRun')
                    if value == 0xFF:
                        return 9
            except FileNotFoundError:
                pass
        
        return 0

    except Exception as e:
        return 0

def check_no_old_activex():
    now = datetime.now()

    ie = win32com.client.Dispatch("InternetExplorer.Application")
    ie.Visible = 0

    old_activex_controls = []

    try:
        activex_controls = ie.Document.getElementsByTagName("object")

        for control in activex_controls:
            last_accessed = datetime.strptime(control.getAttribute("lastAccessed"), "%Y-%m-%d %H:%M:%S")

            if (now - last_accessed).days > 90:
                old_activex_controls.append(control)

        if len(old_activex_controls) == 0:
            return 9
        else:
            return 0
    except Exception as e:
        return 0

def check_no_unsigned_processes():
    try:
        process_list_result = subprocess.run(
            ['wmic', 'process', 'get', 'ProcessId,ExecutablePath'],
            capture_output=True, text=True, encoding='utf-8', errors='ignore'
        )
        process_list = process_list_result.stdout.strip().split('\n')[1:]
    except Exception as e:
        return 0

    unsigned_processes = []

    for line in process_list:
        parts = re.split(r'\s{2,}', line.strip())
        if len(parts) != 2:
            continue

        pid, exe = parts
        if not exe:
            continue

        try:
            result = subprocess.run(
                ['sigcheck.exe', '-accepteula', exe],
                capture_output=True, text=True, encoding='utf-8', errors='ignore'
            )
            if "Verified" not in result.stdout or "Unsigned" in result.stdout:
                unsigned_processes.append((pid, exe))
        except Exception as e:
            pass

    if not unsigned_processes:
        return 9
    else:
        return 0

def get_file_version(file_path):
    try:
        result = subprocess.run(
            ['powershell', '-Command', f"(Get-Item '{file_path}').VersionInfo.ProductVersion"],
            capture_output=True, text=True
        )
        version = result.stdout.strip()
        return version if version else None
    except Exception as e:
        return None

def version_string_to_list(version):
    return list(map(int, version.replace(",", ".").split(".")))

def check_program_version(program_name, file_path, latest_version):
    installed_version = get_file_version(file_path)
    if installed_version:
        installed_version_list = version_string_to_list(installed_version)
        latest_version_list = version_string_to_list(latest_version)
        if installed_version_list >= latest_version_list:
            return True, installed_version
        else:
            return False, installed_version
    else:
        return None, None
    
def check_main_software_updated():
    latest_versions = {
        "한컴오피스 한글": ("C:\\Program Files (x86)\\Hnc\\HOffice9\\Bin\\Hwp.exe", "9.1.1.5656"),
        "Acrobat Reader": ("C:\\Program Files\\Adobe\\Acrobat DC\\Acrobat\\Acrobat.exe", "24.002.20933")
    }

    results = {}
    for program, (file_path, latest_version) in latest_versions.items():
        if os.path.exists(file_path):
            is_updated, installed_version = check_program_version(program, file_path, latest_version)
            results[program] = (is_updated, installed_version, latest_version)
        else:
            results[program] = (None, None, latest_version)
    
    return results

def perform_checks():
    results = {}

    results['password_set'] = check_password_set()
    results['password_age'] = check_password_age()
    results['screensaver_set'] = check_screensaver_set()
    results['no_shared_folders'] = check_no_shared_folders()
    results['os_updated'] = check_os_updated()
    results['antivirus_installed'] = check_antivirus_installed()
    results['antivirus_updated'] = check_antivirus_updated()
    results['usb_autorun_disabled'] = check_usb_autorun_disabled()
    results['no_old_activex'] = check_no_old_activex()
    results['no_unsigned_processes'] = check_no_unsigned_processes()
    results['software_updates'] = check_main_software_updated()
    
    score = 0
        
    if results['password_set']:
        score += 10
    if results['password_age'] == 9:
        score += 10
    if results['screensaver_set'] == 9:
        score += 10
    if results['no_shared_folders'] == 9:
        score += 10
    if results['os_updated'] == 9:
        score += 10
    if results['antivirus_installed'] == 9:
        score += 10
    if results['antivirus_updated'] == 9:
        score += 10
    if results['usb_autorun_disabled']:
        score += 10
    if results['no_old_activex']:
        score += 10
    if results['no_unsigned_processes'] == 9:
        score += 10

    return score, results

def display_results(score, results):
    if score >= 90:
        security_level = "안전"
    elif score >= 80:
        security_level = "보통"
    else:
        security_level = "위험"
    
    pie_chart_canvas.delete("all")
    pie_chart_canvas.create_arc((10, 10, 190, 190), start=0, extent=(score / 100) * 360, fill="green")
    pie_chart_canvas.create_arc((10, 10, 190, 190), start=(score / 100) * 360, extent=(1 - score / 100) * 360, fill="red")
    
    result_label.config(text=f"PC점검 결과 : {score}점")
    security_level_label.config(text=f"PC의 보안수준은 {security_level}입니다.")

    update_tab_contents(results)

def update_tab_contents(results):
    def on_item_click(event, tab_name):
        item = event.widget.selection()
        if not item:
            return
        item = item[0]
        values = event.widget.item(item, "values")

        if tab_name == 'account_security':
            if values[0] == "로그인 패스워드 설정" and values[1] == "미설정":
                open_password_settings()
            elif values[0] == "패스워드 변경 여부" and values[1] == "3개월 초과":
                open_password_change()
            elif values[0] == "화면보호기 설정 여부" and values[1] == "미설정":
                open_screensaver_settings()
        elif tab_name == 'windows_security':
            if values[0] == "사용자 공유 폴더 제거" and values[1] == "있음":
                remove_shared_folders()
            elif values[0] == "운영체제 최신 보안 업데이트 여부" and values[1] == "미설치":
                open_windows_update()
        elif tab_name == 'antivirus':
            if values[0] == "바이러스 백신 설치 및 실행 여부" and values[1] == "미설치":
                open_antivirus_download_sites()
            elif values[0] == "바이러스 백신의 최신 업데이트 여부":
                if values[1] == "미설치":
                    if results['antivirus_installed'] == 0:
                        open_antivirus_download_sites()
                    else:
                        run_installed_antivirus()
        elif tab_name == 'other_security':
            if values[0] == "USB 자동 실행 방지" and values[1] == "활성화":
                open_usb_autorun_settings()
            elif values[0] == "미사용(3개월) ActiveX 프로그램 제거 여부" and values[1] == "있음":
                open_inactive_activex_list()
            elif values[0] == "서명되지 않은 프로세스 점검" and values[1] == "있음":
                open_unsigned_process_list()
        elif tab_name == 'vulnerabilities':
            if "한컴오피스 한글 최신버전 여부" in values[0] and values[1] == "미설치":
                webbrowser.open("https://www.hancom.com/cs_center/csDownload.do")
            elif "Acrobat Reader 최신버전 여부" in values[0] and values[1] == "미설치":
                webbrowser.open("https://helpx.adobe.com/kr/acrobat/kb/update-acrobat-manually.html")
            elif "최신 보안공지를 확인하여 취약점 정보에 주의하세요!" in values[0]:
                webbrowser.open("https://knvd.krcert.or.kr/securityNotice.do")

    # '2. 계정 보안관리' 탭 업데이트
    account_security_tab = tabs[1]
    for widget in account_security_tab.winfo_children():
        widget.destroy()

    tree_account_security = ttk.Treeview(account_security_tab, columns=("Type", "Status"), show='headings')
    tree_account_security.heading("Type", text="점검항목")
    tree_account_security.heading("Status", text="점검결과")
    tree_account_security.column("Type", width=200, anchor='w')
    tree_account_security.column("Status", width=150, anchor='w')

    data = [
        ("로그인 패스워드 설정", '설정' if results['password_set'] else '미설정'),
        ("패스워드 변경 여부", 
            '3개월 이내 변경됨' if results['password_age'] == 9 
            else '3개월 초과' if results['password_age'] == 0 
            else '패스워드 미설정')
    ]

    for item in data:
        color = 'green' if (item[0] == "로그인 패스워드 설정" and results['password_set']) or (item[0] == "패스워드 변경 여부" and results['password_age'] == 9) else 'red'
        tree_account_security.insert("", tk.END, values=item, tags=(color,))

    screensaver_status = "설정" if results['screensaver_set'] == 9 else "미설정"
    color = 'green' if results['screensaver_set'] == 9 else 'red'
    tree_account_security.insert("", tk.END, values=("화면보호기 설정 여부", screensaver_status), tags=(color,))

    tree_account_security.tag_configure('green', background='light green')
    tree_account_security.tag_configure('red', background='light coral')

    tree_account_security.pack(padx=10, pady=10, fill='both', expand=True)
    tree_account_security.bind("<Double-1>", lambda event: on_item_click(event, 'account_security'))

    # '3. 윈도우즈 보안관리' 탭 업데이트
    windows_security_tab = tabs[2]
    for widget in windows_security_tab.winfo_children():
        widget.destroy()

    tree_windows_security = ttk.Treeview(windows_security_tab, columns=("Type", "Status"), show='headings')
    tree_windows_security.heading("Type", text="점검항목")
    tree_windows_security.heading("Status", text="점검결과")
    tree_windows_security.column("Type", width=300, anchor='w')
    tree_windows_security.column("Status", width=150, anchor='w')

    data = [
        ("사용자 공유 폴더 제거", '없음' if results['no_shared_folders'] == 9 else '있음'),
        ("운영체제 최신 보안 업데이트 여부", '최신' if results['os_updated'] == 9 else '미설치')
    ]

    for item in data:
        color = 'green' if (item[0] == "사용자 공유 폴더 제거" and item[1] == '없음') or (item[0] == "운영체제 최신 보안 업데이트 여부" and item[1] == '최신') else 'red'
        tree_windows_security.insert("", tk.END, values=item, tags=(color,))

    tree_windows_security.tag_configure('green', background='light green')
    tree_windows_security.tag_configure('red', background='light coral')

    tree_windows_security.pack(padx=10, pady=10, fill='both', expand=True)
    tree_windows_security.bind("<Double-1>", lambda event: on_item_click(event, 'windows_security'))

    # '4. 악성코드 예방' 탭 업데이트
    antivirus_tab = tabs[3]
    for widget in antivirus_tab.winfo_children():
        widget.destroy()

    tree_antivirus = ttk.Treeview(antivirus_tab, columns=("Type", "Status"), show='headings')
    tree_antivirus.heading("Type", text="점검항목")
    tree_antivirus.heading("Status", text="점검결과")
    tree_antivirus.column("Type", width=300, anchor='w')
    tree_antivirus.column("Status", width=150, anchor='w')

    data = []

    if results['antivirus_installed'] == 9:
        antivirus_status = '설치'
        if results['antivirus_updated'] == 9:
            update_status = '최신'
        else:
            update_status = '미설치'
    else:
        antivirus_status = '미설치'
        update_status = '미설치'

    data.append(("바이러스 백신 설치 및 실행 여부", antivirus_status))
    data.append(("바이러스 백신의 최신 업데이트 여부", update_status))

    for item in data:
        color = 'green' if (item[0] == "바이러스 백신 설치 및 실행 여부" and item[1] == '설치') or \
                          (item[0] == "바이러스 백신의 최신 업데이트 여부" and item[1] == '최신') else 'red'
        tree_antivirus.insert("", tk.END, values=item, tags=(color,))

    tree_antivirus.tag_configure('green', background='light green')
    tree_antivirus.tag_configure('red', background='light coral')

    tree_antivirus.pack(padx=10, pady=10, fill='both', expand=True)
    tree_antivirus.bind("<Double-1>", lambda event: on_item_click(event, 'antivirus'))

    # '5. 기타 보안관리' 탭 업데이트
    other_security_tab = tabs[4]
    for widget in other_security_tab.winfo_children():
        widget.destroy()

    tree_other_security = ttk.Treeview(other_security_tab, columns=("Type", "Status"), show='headings')
    tree_other_security.heading("Type", text="점검항목")
    tree_other_security.heading("Status", text="점검결과")
    tree_other_security.column("Type", width=300, anchor='w')
    tree_other_security.column("Status", width=150, anchor='w')

    data = []

    if results['usb_autorun_disabled']:
        data.append(("USB 자동 실행 방지", "방지"))
    else:
        data.append(("USB 자동 실행 방지", "활성화"))

    if results['no_old_activex']:
        data.append(("미사용(3개월) ActiveX 프로그램 제거 여부", "없음"))
    else:
        data.append(("미사용(3개월) ActiveX 프로그램 제거 여부", "있음"))

    if results['no_unsigned_processes'] == 9:
        data.append(("서명되지 않은 프로세스 점검", "없음"))
    else:
        data.append(("서명되지 않은 프로세스 점검", "있음"))

    for item in data:
        color = 'green' if (item[1] == '방지' or item[1] == '없음') else 'red'
        tree_other_security.insert("", tk.END, values=item, tags=(color,))

    tree_other_security.tag_configure('green', background='light green')
    tree_other_security.tag_configure('red', background='light coral')

    tree_other_security.pack(padx=10, pady=10, fill='both', expand=True)
    tree_other_security.bind("<Double-1>", lambda event: on_item_click(event, 'other_security'))

    # '6. 신규 보안취약점 자동진단' 탭 업데이트
    vulnerabilities_tab = tabs[5]
    for widget in vulnerabilities_tab.winfo_children():
        widget.destroy()

    tree_vulnerabilities = ttk.Treeview(vulnerabilities_tab, columns=("Type", "Status"), show='headings')
    tree_vulnerabilities.heading("Type", text="점검항목")
    tree_vulnerabilities.heading("Status", text="점검결과")
    tree_vulnerabilities.column("Type", width=300, anchor='w')
    tree_vulnerabilities.column("Status", width=150, anchor='w')

    data = []
    for program, (is_updated, installed_version, latest_version) in results['software_updates'].items():
        if is_updated is None:
            data.append((f"{program} 최신버전 여부", "없음"))
        elif is_updated:
            data.append((f"{program} 최신버전 여부", "최신"))
        else:
            data.append((f"{program} 최신버전 여부", "미설치"))

    for item in data:
        color = 'green' if item[1] == '최신' else 'red'
        tree_vulnerabilities.insert("", tk.END, values=item, tags=(color,))

    tree_vulnerabilities.tag_configure('green', background='light green')
    tree_vulnerabilities.tag_configure('red', background='light coral')

    # 최신 보안공지 추가
    tree_vulnerabilities.insert("", tk.END, values=("최신 보안공지를 확인하여 취약점 정보에 주의하세요!", ""), tags=('red',))

    tree_vulnerabilities.pack(padx=10, pady=10, fill='both', expand=True)
    tree_vulnerabilities.bind("<Double-1>", lambda event: on_item_click(event, 'vulnerabilities'))

def check_button_clicked():
    score, results = perform_checks()
    display_results(score, results)

def exit_button_clicked():
    root.quit()

def open_password_settings():
    try:
        subprocess.run(["powershell", "-Command", "Start-Process", "control", "-ArgumentList", "userpasswords"], check=True)
    except subprocess.CalledProcessError as e:
        messagebox.showerror("Error", f"Failed to open settings: {e}")

def open_password_change():
    try:
        subprocess.run(["powershell", "-Command", "Start-Process", "control", "-ArgumentList", "userpasswords2"], check=True)
    except subprocess.CalledProcessError as e:
        messagebox.showerror("Error", f"Failed to open settings: {e}")

def open_screensaver_settings():
    try:
        subprocess.run(["powershell", "-Command", "Start-Process", "control", "-ArgumentList", '"desk.cpl,,@screensaver"'], check=True)
    except subprocess.CalledProcessError as e:
        messagebox.showerror("Error", f"Failed to open settings: {e}")

def open_windows_update():
    try:
        subprocess.run(["powershell", "-Command", "Start-Process", "ms-settings:windowsupdate"], check=True)
    except subprocess.CalledProcessError as e:
        messagebox.showerror("Error", f"Failed to open update settings: {e}")

def remove_shared_folders():
    try:
        # Run the command to list shared folders
        result = subprocess.run(['net', 'share'], stdout=subprocess.PIPE, text=True)
        output = result.stdout

        # Print the entire output for debugging purposes
        print("net share output:\n", output)

        # Split output into lines
        lines = output.splitlines()

        # Define default shares
        default_shares = {"ADMIN$", "C$", "IPC$", "D$", "E$", "F$", "G$", "H$", "I$", "J$", "K$", "L$", "M$", "N$", "O$", "P$", "Q$", "R$", "S$", "T$", "U$", "V$", "W$", "X$", "Y$", "Z$"}
        user_shares = []

        # Use a regex pattern to match valid share names
        share_pattern = re.compile(r'^[A-Za-z0-9$_.-]+$')

        # Skip the first few lines that contain the header and separator
        for line in lines[4:]:  # Start checking from the 5th line
            parts = line.split()
            if len(parts) > 0:
                share_name = parts[0]
                print("Found share:", share_name)  # Print each share name for debugging
                # Check if the share name is valid and not in default shares
                if share_pattern.match(share_name) and share_name not in default_shares and not share_name.startswith('---'):
                    user_shares.append(share_name)
                    print("User share detected:", share_name)  # Print detected user share

        # 사용자 공유 폴더 제거
        for share in user_shares:
            try:
                subprocess.run(["powershell", "-Command", f"Remove-SmbShare -Name '{share}' -Confirm:$false"], check=True)
                print(f"Removed share: {share}")
            except subprocess.CalledProcessError as e:
                print(f"Failed to remove share {share}: {e}")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to remove shared folders: {e}")
        
def open_antivirus_download_sites():
    try:
        webbrowser.open("https://www.estsecurity.com/public/product/alyac")
        webbrowser.open("https://v3litecontents.ahnlab.com/v3lite.html")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to open download sites: {e}")

def run_installed_antivirus():
    alyac_path = "C:\\Program Files\\ESTsoft\\ALYac\\AYLaunch.exe"
    v3lite_path = "C:\\Program Files\\AhnLab\\V3Lite\\V3Lite.exe"
    
    try:
        if os.path.exists(alyac_path):
            subprocess.run(["powershell", "-Command", f"Start-Process '{alyac_path}'"], check=True)
        elif os.path.exists(v3lite_path):
            subprocess.run(["powershell", "-Command", f"Start-Process '{v3lite_path}'"], check=True)
        else:
            messagebox.showerror("Error", "No antivirus software found.")
    except subprocess.CalledProcessError as e:
        messagebox.showerror("Error", f"Failed to run antivirus: {e}")

def open_usb_autorun_settings():
    try:
        webbrowser.open("https://ssv.skill.or.kr/kisa-windows-mac-pc-security-guide/kisa-windows-pc-security-vulnerability")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to open download sites: {e}")

def open_inactive_activex_list():
    try:
        webbrowser.open("https://ssv.skill.or.kr/kisa-windows-mac-pc-security-guide/kisa-windows-pc-security-vulnerability")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to open download sites: {e}")

def open_unsigned_process_list():
    try:
        webbrowser.open("https://ssv.skill.or.kr/kisa-windows-mac-pc-security-guide/kisa-windows-pc-security-vulnerability")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to open download sites: {e}")

root = tk.Tk()
root.title("PC 보안 점검 도구 v1.0")

tab_control = ttk.Notebook(root)
tab_titles = [
    "1. PC 보안수준", "2. 계정 보안관리", "3. 윈도우즈 보안관리", 
    "4. 악성코드 예방", "5. 기타 보안관리", "6. 신규 보안취약점 자동진단", "7. 프로그램 정보"
]
tabs = [ttk.Frame(tab_control) for _ in tab_titles]
for tab, title in zip(tabs, tab_titles):
    tab_control.add(tab, text=title)
tab_control.pack(expand=1, fill="both")

pc_security_tab = tabs[0]
pc_security_tab_upper = ttk.Frame(pc_security_tab)
pc_security_tab_upper.pack(fill="both", expand=True)

pie_chart_canvas = tk.Canvas(pc_security_tab_upper, width=200, height=200)
pie_chart_canvas.pack()

pc_security_tab_lower = ttk.Frame(pc_security_tab)
pc_security_tab_lower.pack(fill="both", expand=True)

result_label = tk.Label(pc_security_tab_lower, text="PC점검 결과 : 00점")
result_label.pack()

security_level_label = tk.Label(pc_security_tab_lower, text="PC의 보안수준은 00입니다.")
security_level_label.pack()

program_info_tab = tabs[6]
program_info_tab_upper = ttk.Frame(program_info_tab)
program_info_tab_upper.pack(fill="both", expand=True)

info_table = ttk.Treeview(program_info_tab_upper, columns=("1", "2"), show='headings', height=6)
info_table.heading("1", text="항목")
info_table.heading("2", text="내용")
info_table.column("1", width=150, anchor="center")
info_table.column("2", width=300, anchor="center")

info_data = [
    ("버전", "PC 보안 점검 도구 v1.0"),
    ("배포일", "2024년 8월 7일 수요일"),
    ("만든곳", "대전대신고등학교 A.M.E.N."),
    ("지도교사", "신환용 선생님"),
    ("개발자", "최용호, 정민우, 조승현")
]

for item in info_data:
    info_table.insert("", "end", values=item)

info_table.pack(fill="both", expand=True)

button_frame = ttk.Frame(root)
button_frame.pack(fill="x")

check_button = tk.Button(button_frame, text="점검", command=check_button_clicked)
check_button.pack(side="left")

exit_button = tk.Button(button_frame, text="종료", command=exit_button_clicked)
exit_button.pack(side="right")

root.mainloop()