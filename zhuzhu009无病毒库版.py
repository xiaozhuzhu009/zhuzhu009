import tkinter as tk
from tkinter import filedialog, messagebox, font
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
import os
import hashlib
import sys
import requests
import threading
import time
import random
import queue
import socket
import gc
import ctypes
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
import signal  # 用于超时控制

# -------------------------- 基础配置 --------------------------
INSTANCE_PORT = 65432
VIRUS_DB_UPDATE_DATE = "2025.08.17 9:11"
MAX_YARA_THREADS = 2  # 限制启发式扫描线程数量
YARA_SCAN_TIMEOUT = 15  # 启发式扫描超时时间(秒)
MAX_YARA_RULES_PER_BATCH = 10  # 每批处理的启发式规则数量

# 获取资源文件路径（支持打包后访问）
def get_resource_path(relative_path):
    """获取资源文件的正确路径，无论是否打包"""
    if getattr(sys, 'frozen', False):
        base_path = sys._MEIPASS
    else:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

# 数据库路径 - 使用资源路径函数
DEFAULT_VIRUS_DB = get_resource_path("1.txt")  # 病毒库
DEFAULT_WHITELIST = get_resource_path("2.txt")  # 白名单
DEFAULT_AD_DB = get_resource_path("3.txt")      # 广告库

# 启发式规则路径配置
MAIN_YARA_RULE = get_resource_path("yara-rules-full.yar")
MBYARA_FOLDER = get_resource_path("mbyara")

# 全局状态变量
is_scanning = False
pause_scanning = False
stop_scanning = False
cloud_scan_threads = 0
total_scanned_files = 0
scanned_files_count = 0  # 新增：已扫描文件计数

log_queue = queue.Queue()
ui_initialized = False  # 标记UI是否初始化完成

# SHA256验证正则表达式
SHA256_PATTERN = re.compile(r'^[0-9a-fA-F]{64}$')

# -------------------------- 启发式模块检查 --------------------------
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    def log(msg):
        print(msg)
    print("警告: 启发模块未安装，启发式扫描功能将不可用")


# -------------------------- 核心工具函数 --------------------------
def normalize_path(path):
    """标准化文件路径"""
    if not path:
        return ""
    return os.path.abspath(os.path.normpath(path))


def get_short_pathname(long_path):
    """获取Windows短路径名（解决中文路径问题）"""
    if sys.platform != "win32" or not long_path:
        return long_path
        
    try:
        buf = ctypes.create_unicode_buffer(512)
        ctypes.windll.kernel32.GetShortPathNameW(long_path, buf, 512)
        short_path = buf.value
        return short_path if short_path else long_path
    except Exception as e:
        print(f"获取短路径失败: {str(e)} - {long_path}")
        return long_path


def log_worker(app):
    """日志处理线程"""
    global ui_initialized
    try:
        while True:
            msg = log_queue.get_nowait()
            if ui_initialized and app.text_box:
                # 将日志添加到完整日志列表
                app.full_log.append(msg)
                
                # 如果当前是显示所有日志模式，才实时添加到文本框
                if getattr(app, 'current_log_filter', 'all') == 'all':
                    app.text_box.config(state=tk.NORMAL)
                    app.text_box.insert(tk.END, msg + "\n\n")
                    max_lines = 500
                    current_lines = int(app.text_box.index('end-1c').split('.')[0])
                    if current_lines > max_lines:
                        app.text_box.delete('1.0', f'{current_lines - max_lines}.0')
                    app.text_box.see(tk.END)
                    app.text_box.config(state=tk.DISABLED)
    except queue.Empty:
        pass
    app.root.after(200, lambda: log_worker(app))


def log(msg):
    """日志输出（UI和CMD）"""
    global ui_initialized
    print(msg)
    if ui_initialized and VirusScanApp.instance and VirusScanApp.instance.text_box:
        log_queue.put(msg)


# -------------------------- 数据库加载核心函数 --------------------------
def load_database(file_path, db_name):
    """增强版数据库加载函数"""
    db_dict = {}
    file_path = normalize_path(file_path)
    
    if not os.path.exists(file_path):
        log(f"错误: {db_name}文件不存在 - {file_path}")
        return db_dict, False
    
    if not os.path.isfile(file_path):
        log(f"错误: {db_name}不是有效文件 - {file_path}")
        return db_dict, False
    
    try:
        file_size = os.path.getsize(file_path)
        if file_size == 0:
            log(f"警告: {db_name}文件为空 - {file_path}")
            return db_dict, False
    except Exception as e:
        log(f"错误: 无法获取{db_name}文件大小 - {str(e)}")
        return db_dict, False
    
    content = None
    tried_paths = []
    success = False
    
    paths_to_try = [file_path]
    if sys.platform == "win32":
        short_path = get_short_pathname(file_path)
        if short_path not in paths_to_try:
            paths_to_try.append(short_path)
    
    encodings_to_try = ["utf-8", "gbk", "gb2312", "utf-16"]
    
    for path in paths_to_try:
        tried_paths.append(path)
        for encoding in encodings_to_try:
            try:
                with open(path, "r", encoding=encoding) as f:
                    content = f.readlines()
                success = True
                log(f"成功读取{db_name} (路径: {os.path.basename(path)}, 编码: {encoding})")
                break
            except UnicodeDecodeError:
                continue
            except Exception as e:
                log(f"读取{db_name}失败 (路径: {path}, 编码: {encoding}) - {str(e)}")
                continue
        if success:
            break
    
    if not success:
        log(f"严重错误: 所有尝试都无法读取{db_name}，已尝试路径: {tried_paths}")
        return db_dict, False
    
    valid_entries = 0
    invalid_entries = 0
    is_virus_db = "病毒库" in db_name
    is_ad_db = "广告库" in db_name
    support_both_formats = is_virus_db or is_ad_db
    
    for line_num, line in enumerate(content, 1):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
            
        if support_both_formats:
            if SHA256_PATTERN.match(line):
                default_desc = "恶意软件" if is_virus_db else "广告风险文件"
                db_dict[line.lower()] = default_desc
                valid_entries += 1
                continue
            elif ':' in line:
                key, val = line.split(':', 1)
                key = key.strip().lower()
                val = val.strip() or ("恶意软件" if is_virus_db else "广告风险文件")
                if SHA256_PATTERN.match(key):
                    db_dict[key] = val
                    valid_entries += 1
                else:
                    invalid_entries += 1
                    log(f"{db_name}格式错误 (行{line_num}): 无效的SHA256哈希 - {line}")
            else:
                invalid_entries += 1
                log(f"{db_name}格式错误 (行{line_num}): 不是有效的SHA256或'哈希:名称'格式 - {line}")
                
        else:
            if ':' in line:
                key = line.split(':', 1)[0].strip().lower()
            else:
                key = line.strip().lower()
                
            if SHA256_PATTERN.match(key):
                db_dict[key] = "白名单文件"
                valid_entries += 1
            else:
                invalid_entries += 1
                log(f"{db_name}格式错误 (行{line_num}): 无效的SHA256哈希 - {line}")
    
    if valid_entries == 0:
        log(f"警告: {db_name}中未找到有效记录")
        return db_dict, False
    
    log(f"{db_name}加载完成 - 有效记录: {valid_entries}, 无效记录: {invalid_entries}")
    return db_dict, True


# -------------------------- 启发式规则处理 --------------------------
def load_heuristic_rules():
    """加载启发式规则并分组处理"""
    if not YARA_AVAILABLE:
        return [], 0
    
    rules = []
    success_count = 0
    
    # 1. 加载主启发式规则
    if os.path.exists(MAIN_YARA_RULE) and os.path.isfile(MAIN_YARA_RULE):
        try:
            file_path = MAIN_YARA_RULE
            if sys.platform == "win32":
                short_path = get_short_pathname(file_path)
                if short_path and os.path.exists(short_path):
                    file_path = short_path
                    
            compiled = yara.compile(filepath=file_path)
            rules.append((os.path.basename(file_path), compiled))
            success_count += 1
            print(f"已加载主启发式规则: {os.path.basename(file_path)}")
        except Exception as e:
            print(f"主启发式规则加载失败: {e} - {MAIN_YARA_RULE}")
    else:
        print(f"未找到主启发式规则: {MAIN_YARA_RULE}")
    
    # 2. 加载启发式规则文件夹中的规则
    if os.path.exists(MBYARA_FOLDER) and os.path.isdir(MBYARA_FOLDER):
        yar_files = sorted([f for f in os.listdir(MBYARA_FOLDER) 
                          if f.lower().endswith('.yar') and 
                          os.path.isfile(os.path.join(MBYARA_FOLDER, f))])
        
        if yar_files:
            print(f"发现{len(yar_files)}个启发式规则文件在 {MBYARA_FOLDER}")
            
            for yar_file in yar_files:
                try:
                    file_path = os.path.join(MBYARA_FOLDER, yar_file)
                    if sys.platform == "win32":
                        short_path = get_short_pathname(file_path)
                        if short_path and os.path.exists(short_path):
                            file_path = short_path
                            
                    compiled = yara.compile(filepath=file_path)
                    rules.append((yar_file, compiled))
                    success_count += 1
                    print(f"已加载启发式规则: {yar_file}")
                except Exception as e:
                    print(f"启发式规则加载失败 {yar_file}: {e}")
        else:
            print(f"在 {MBYARA_FOLDER} 中未发现启发式规则文件")
    else:
        print(f"启发式规则文件夹不存在: {MBYARA_FOLDER}")
    
    # 将规则分批处理，避免单次加载过多
    batched_rules = []
    for i in range(0, len(rules), MAX_YARA_RULES_PER_BATCH):
        batched_rules.append(rules[i:i+MAX_YARA_RULES_PER_BATCH])
    
    return batched_rules, success_count


def heuristic_scan_worker(rule_batch, file_content):
    """启发式扫描工作线程，带超时控制"""
    try:
        for rule_name, rule in rule_batch:
            matches = rule.match(data=file_content, timeout=YARA_SCAN_TIMEOUT)
            if matches:
                return (True, rule_name, matches[0].rule)
    except Exception as e:
        print(f"启发式扫描错误: {str(e)}")
    return (False, None, None)


def scan_file_with_heuristic(file_path, batched_rules, app):
    """优化的启发式扫描，控制并发和超时"""
    if not YARA_AVAILABLE or not batched_rules:
        return 0
    
    normalized_path = normalize_path(file_path)
    
    if not os.path.exists(normalized_path) or not os.path.isfile(normalized_path):
        return 0
    
    try:
        file_size = os.path.getsize(normalized_path)
        if file_size > 200 * 1024 * 1024:  # 200MB 大文件跳过
            return 0
    except Exception:
        return 0
        
    file_content = None
    try:
        with open(normalized_path, 'rb') as f:
            file_content = f.read()
        
        # 使用线程池控制并发扫描数量
        with ThreadPoolExecutor(max_workers=MAX_YARA_THREADS) as executor:
            futures = []
            
            # 提交每批规则的扫描任务
            for batch in batched_rules:
                futures.append(executor.submit(heuristic_scan_worker, batch, file_content))
                
            # 检查结果，一旦发现匹配就取消剩余任务
            for future in as_completed(futures):
                if future.done():
                    result = future.result()
                    if result[0]:  # 发现匹配
                        # 取消所有未完成的任务
                        for f in futures:
                            if not f.done():
                                f.cancel()
                        
                        log(f"⚠ 本地启发式扫描发现病毒 ({result[2]} in {result[1]}): {normalized_path}")
                        with app.lock_detected_files:
                            app.detected_virus_files.append(normalized_path)
                        return 1
        
    except Exception as e:
        print(f"启发式扫描处理错误: {str(e)}")
    finally:
        if file_content:
            del file_content
            gc.collect()  # 立即释放内存
            
    return 0


# -------------------------- 扫描核心逻辑 --------------------------
def get_file_hash(file_path):
    """获取文件SHA256哈希"""
    normalized_path = normalize_path(file_path)
    try:
        if not os.path.exists(normalized_path) or not os.path.isfile(normalized_path):
            return None
            
        file_size = os.path.getsize(normalized_path)
        if file_size > 200 * 1024 * 1024:  # 200MB 大文件跳过
            return None
    except Exception:
        return None
        
    hash_obj = hashlib.sha256()
    try:
        with open(normalized_path, "rb") as f:
            while chunk := f.read(4096):
                hash_obj.update(chunk)
        return hash_obj.hexdigest()
    except Exception:
        return None


def cloud_scan(sha256):
    """云查杀接口"""
    try:
        response = requests.get(
            f"https://www.filescan.io/api/reputation/hash?sha256={sha256}",
            timeout=10
        )
        if response.status_code != 200:
            return "✔ 本地鉴定文件安全"
        
        data = response.json()
        verdict = data.get("overall_verdict", "").lower()
        if verdict in ["malicious", "likely_malicious"]:
            return "⚠ 云查杀发现病毒"
        elif verdict == "suspicious":
            return "⚠ 文件可疑"
        else:
            return "✔ 云查杀鉴定文件安全"
    except Exception:
        return "✔ 本地鉴定文件安全"


def cloud_scan_thread(sha256, file_path):
    """云扫描线程"""
    global cloud_scan_threads, scanned_files_count
    normalized_path = normalize_path(file_path)
    time.sleep(random.uniform(0.3, 1.0))
    result = cloud_scan(sha256)
    
    def callback():
        global cloud_scan_threads, scanned_files_count
        scanned_files_count += 1
        if "病毒" in result:
            with VirusScanApp.instance.lock_detected_files:
                VirusScanApp.instance.detected_virus_files.append(normalized_path)
        log(f"{result}: {normalized_path}")
        cloud_scan_threads -= 1
        
        # 更新进度条
        VirusScanApp.instance.update_scan_progress()
        
        if cloud_scan_threads <= 0:
            global is_scanning
            is_scanning = False
            VirusScanApp.instance.update_status_label()
            VirusScanApp.instance.btn_scan.config(state=NORMAL)
    
    VirusScanApp.instance.root.after(0, callback)


def scan_files(files, virus_db, whitelist, ad_db, batched_rules, app):
    """扫描文件列表（优化启发式扫描部分）"""
    global scanned_files_count
    scanned_files_count = 0
    
    app.detected_virus_files.clear()
    app.detected_ad_files.clear()
    
    global total_scanned_files, cloud_scan_threads
    total_scanned_files = len(files)
    cloud_scan_threads = 0
    
    # 初始化进度条
    app.update_scan_progress()
    
    for file_path in files:
        if stop_scanning:
            break
        while pause_scanning:
            time.sleep(0.2)
            
        normalized_path = normalize_path(file_path)
        app.update_current_file_label(normalized_path)
        
        # 计算哈希
        sha256 = get_file_hash(normalized_path)
        if not sha256:
            log(f"跳过文件: {normalized_path}")
            scanned_files_count += 1
            app.update_scan_progress()
            continue
        
        # 转为小写哈希进行比较
        sha256_lower = sha256.lower()
        
        # 白名单检查
        if sha256_lower in whitelist:
            log(f"✅ 白名单文件: {normalized_path}")
            scanned_files_count += 1
            app.update_scan_progress()
            continue
        
        # 病毒库检查 - 优先检查
        if sha256_lower in virus_db:
            log(f"⚠ 病毒库匹配 ({virus_db[sha256_lower]}): {normalized_path}")
            with app.lock_detected_files:
                app.detected_virus_files.append(normalized_path)
            scanned_files_count += 1
            app.update_scan_progress()
            continue
        
        # 广告库检查
        if sha256_lower in ad_db:
            log(f"⚠ 广告风险文件 ({ad_db[sha256_lower]}): {normalized_path}")
            with app.lock_detected_ad_files:
                app.detected_ad_files.append(normalized_path)
            scanned_files_count += 1
            app.update_scan_progress()
            continue
        
        # 启发式扫描（优化版本）
        heuristic_result = 0
        if batched_rules:
            heuristic_result = scan_file_with_heuristic(normalized_path, batched_rules, app)
        
        if heuristic_result > 0:
            scanned_files_count += 1
            app.update_scan_progress()
            continue
        
        # 云扫描
        cloud_scan_threads += 1
        threading.Thread(
            target=cloud_scan_thread,
            args=(sha256, normalized_path),
            daemon=True
        ).start()
    
    # 等待云扫描完成
    def wait_cloud():
        if cloud_scan_threads > 0:
            app.root.after(500, wait_cloud)
        else:
            global is_scanning
            is_scanning = False
            app.update_status_label()
            app.update_current_file_label("扫描完成")
            app.btn_scan.config(state=NORMAL)
    wait_cloud()


def scan_directory(path, virus_db, whitelist, ad_db, batched_rules, app):
    """扫描目录"""
    normalized_path = normalize_path(path)
    files = []
    
    if not os.path.exists(normalized_path) or not os.path.isdir(normalized_path):
        log(f"扫描目录无效: {normalized_path}")
        app.btn_scan.config(state=NORMAL)
        return
        
    try:
        scan_path = normalized_path
        if sys.platform == "win32":
            short_path = get_short_pathname(normalized_path)
            if short_path and os.path.exists(short_path):
                scan_path = short_path
                
        for root, _, fnames in os.walk(scan_path):
            normalized_root = normalize_path(root)
            for fn in fnames:
                file_path = normalize_path(os.path.join(normalized_root, fn))
                files.append(file_path)
        log(f"发现{len(files)}个文件待扫描")
        scan_files(files, virus_db, whitelist, ad_db, batched_rules, app)
    except Exception as e:
        log(f"目录扫描错误: {str(e)}")
        app.btn_scan.config(state=NORMAL)


# -------------------------- 主应用类 --------------------------
class VirusScanApp:
    instance = None

    def __init__(self):
        global ui_initialized
        VirusScanApp.instance = self
        self.lock_detected_files = threading.Lock()
        self.lock_detected_ad_files = threading.Lock()
        self.detected_virus_files = []
        self.detected_ad_files = []
        
        # 新增：跟踪当前日志过滤模式
        self.current_log_filter = 'all'

        # 加载数据库
        self.virus_db, self.virus_db_loaded = load_database(DEFAULT_VIRUS_DB, "病毒库(1.txt)")
        self.whitelist, _ = load_database(DEFAULT_WHITELIST, "白名单(2.txt)")
        self.ad_db, self.ad_db_loaded = load_database(DEFAULT_AD_DB, "广告库(3.txt)")
        
        # 初始化UI
        self.root = ttk.Window(themename="darkly")  # 更改为深色主题，更适合安全类应用
        self.root.title("zhuzhu009 病毒扫描器")
        self.root.geometry("1280x960")
        self.root.minsize(800, 600)
        self.root.protocol("WM_DELETE_WINDOW", self.quit_app)
        
        # 添加图标
        try:
            self.root.iconbitmap(default="shield.ico")  # 假设存在shield.ico图标文件
        except:
            pass  # 忽略图标加载错误

        # 状态变量
        self.folder_path = tk.StringVar()
        self.file_path = tk.StringVar()
        self.status_var = tk.StringVar()
        self.cloud_status = tk.StringVar(value="云查杀连接中...")
        self.current_file_var = tk.StringVar()
        self.heuristic_enabled = tk.BooleanVar(value=True)
        self.scan_progress_var = tk.DoubleVar(value=0)  # 扫描进度变量

        # 创建UI组件
        self._create_widgets()
        ui_initialized = True
        log("UI初始化完成")

        # 启动日志处理线程
        self.root.after(200, lambda: log_worker(self))

        # 初始化状态
        self.update_status_label()
        self.check_cloud_connectivity()

        # 检查数据库加载状态并提示
        self.check_database_status()

    def _create_widgets(self):
        """创建UI组件"""
        # 设置统一字体
        default_font = font.Font(family="Microsoft YaHei", size=10)
        title_font = font.Font(family="Microsoft YaHei", size=12, weight="bold")
        
        # 创建主容器，添加内边距
        main_container = ttk.Frame(self.root, padding=10)
        main_container.pack(fill=BOTH, expand=True)
        
        # 顶部标题区域
        header_frame = ttk.Frame(main_container)
        header_frame.pack(fill=X, pady=(0, 15))
        
        # 应用标题和图标
        title_frame = ttk.Frame(header_frame)
        title_frame.pack(side=LEFT)
        
        ttk.Label(
            title_frame, 
            text="🛡️ zhuzhu009病毒扫描器", 
            font=("Arial", 20, "bold"),
            foreground="#4CAF50"
        ).pack(side=LEFT)
        
        ttk.Label(
            title_frame, 
            text="", 
            font=("Arial", 10),
            foreground="#bbb"
        ).pack(side=LEFT, padx=5, pady=5)
        
        # 病毒库更新日期
        ttk.Label(
            header_frame,
            text=f"本地病毒库更新日期: {VIRUS_DB_UPDATE_DATE}",
            foreground="#aaa",
            font=default_font
        ).pack(anchor=tk.NE)

        # 扫描目标选择区 - 使用卡片式设计
        target_frame = ttk.LabelFrame(main_container, text="扫描目标", padding=15)
        target_frame.pack(fill=X, pady=(0, 15))
        
        # 文件选择
        file_frame = ttk.Frame(target_frame)
        file_frame.pack(fill=X, pady=(0, 10))
        ttk.Label(file_frame, text="扫描文件：", font=default_font).pack(side=LEFT, padx=(0, 5))
        
        file_entry_frame = ttk.Frame(file_frame)
        file_entry_frame.pack(side=LEFT, fill=X, expand=True, padx=(0, 5))
        
        ttk.Entry(
            file_entry_frame, 
            textvariable=self.file_path,
            font=default_font
        ).pack(side=LEFT, fill=X, expand=True)
        
        browse_file_btn = ttk.Button(
            file_frame, 
            text="浏览...",
            command=lambda: self.file_path.set(";".join(filedialog.askopenfilenames())),
            style="Primary.TButton"
        )
        browse_file_btn.pack(side=LEFT)

        # 目录选择
        dir_frame = ttk.Frame(target_frame)
        dir_frame.pack(fill=X)
        ttk.Label(dir_frame, text="扫描目录：", font=default_font).pack(side=LEFT, padx=(0, 5))
        
        dir_entry_frame = ttk.Frame(dir_frame)
        dir_entry_frame.pack(side=LEFT, fill=X, expand=True, padx=(0, 5))
        
        ttk.Entry(
            dir_entry_frame, 
            textvariable=self.folder_path,
            font=default_font
        ).pack(side=LEFT, fill=X, expand=True)
        
        browse_dir_btn = ttk.Button(
            dir_frame, 
            text="浏览...",
            command=lambda: self.folder_path.set(filedialog.askdirectory()),
            style="Primary.TButton"
        )
        browse_dir_btn.pack(side=LEFT)

        # 当前扫描文件 - 使用高亮背景
        current_file_frame = ttk.Frame(main_container, padding=8, style="Info.TFrame")
        current_file_frame.pack(fill=X, pady=(0, 10))
        
        ttk.Label(
            current_file_frame, 
            text="当前扫描:", 
            font=default_font,
            foreground="#2196F3"
        ).pack(side=LEFT, padx=(0, 5))
        
        ttk.Label(
            current_file_frame, 
            textvariable=self.current_file_var,
            font=default_font,
            wraplength=900
        ).pack(side=LEFT, fill=X, expand=True)

        # 扫描进度条
        progress_frame = ttk.Frame(main_container)
        progress_frame.pack(fill=X, pady=(0, 10))
        
        self.scan_progress = ttk.Progressbar(
            progress_frame,
            variable=self.scan_progress_var,
            maximum=100,
            length=100,
            mode='determinate',
            style="Success.TProgressbar"
        )
        self.scan_progress.pack(side=LEFT, fill=X, expand=True)
        
        self.progress_label = ttk.Label(
            progress_frame, 
            text="0%", 
            font=default_font,
            width=5
        )
        self.progress_label.pack(side=LEFT, padx=5)

        # 按钮区 - 改进布局和样式
        btn_frame = ttk.Frame(main_container, padding=10)
        btn_frame.pack(fill=X, pady=(0, 10))
        
        # 使用样式增强按钮视觉效果
        btn_style = ttk.Style()
        btn_style.configure("Scan.TButton", font=default_font, padding=8)
        btn_style.configure("Delete.TButton", font=default_font, padding=8)
        
        # 主要操作按钮
        action_buttons = ttk.Frame(btn_frame)
        action_buttons.pack(side=LEFT)
        
        self.btn_scan = ttk.Button(
            action_buttons, 
            text="开始扫描", 
            width=12, 
            command=self.start_scan, 
            style="Success.TButton"
        )
        self.btn_scan.pack(side=LEFT, padx=5)
        
        self.btn_pause = ttk.Button(
            action_buttons, 
            text="暂停扫描", 
            width=12, 
            command=self.pause_scan, 
            style="Warning.TButton"
        )
        self.btn_pause.pack(side=LEFT, padx=5)
        
        self.btn_stop = ttk.Button(
            action_buttons, 
            text="停止扫描", 
            width=12, 
            command=self.stop_scan, 
            style="Danger.TButton"
        )
        self.btn_stop.pack(side=LEFT, padx=5)
        
        # 删除按钮
        delete_buttons = ttk.Frame(btn_frame)
        delete_buttons.pack(side=LEFT, padx=20)
        
        self.btn_delete = ttk.Button(
            delete_buttons, 
            text="删除病毒文件", 
            width=14, 
            command=self.delete_virus_files, 
            style="Danger.TButton"
        )
        self.btn_delete.pack(side=LEFT, padx=5)
        
        self.btn_delete_ad = ttk.Button(
            delete_buttons, 
            text="删除广告文件", 
            width=14, 
            command=self.delete_ad_files, 
            style="Warning.TButton"
        )
        self.btn_delete_ad.pack(side=LEFT, padx=5)
        
        # 启发式扫描开关 - 放在右侧
        heuristic_frame = ttk.Frame(btn_frame)
        heuristic_frame.pack(side=RIGHT)
        
        ttk.Checkbutton(
            heuristic_frame, 
            text="启用启发式扫描", 
            variable=self.heuristic_enabled,
            style="Switch.TCheckbutton"
        ).pack(side=RIGHT)

        # 状态区 - 使用卡片布局
        status_card = ttk.LabelFrame(main_container, text="系统状态", padding=10)
        status_card.pack(fill=X, pady=(0, 10))
        
        # 云状态
        cloud_frame = ttk.Frame(status_card)
        cloud_frame.pack(side=LEFT, padx=10)
        
        cloud_status_icon = ttk.Label(cloud_frame, text="☁", font=("Arial", 16))
        cloud_status_icon.pack(side=LEFT, padx=(0, 5))
        
        ttk.Label(
            cloud_frame, 
            textvariable=self.cloud_status, 
            font=default_font
        ).pack(side=LEFT)
        
        # 数据库状态
        db_status_frame = ttk.Frame(status_card)
        db_status_frame.pack(side=LEFT, padx=15)
        
        self.virus_db_status = ttk.Label(
            db_status_frame,
            text="病毒库状态：加载中...",
            foreground="darkred",
            font=default_font
        )
        self.virus_db_status.pack(side=LEFT, padx=10)
        
        self.ad_db_status = ttk.Label(
            db_status_frame,
            text="广告库状态：加载中...",
            foreground="darkorange",
            font=default_font
        )
        self.ad_db_status.pack(side=LEFT, padx=10)

        # 扫描状态
        self.label_status = ttk.Label(
            main_container, 
            textvariable=self.status_var,
            font=title_font,
            foreground="#4CAF50"
        )
        self.label_status.pack(pady=(0, 10), anchor=W)

        # 日志区 - 使用更现代的外观
        log_frame = ttk.LabelFrame(main_container, text="扫描日志", padding=10)
        log_frame.pack(fill=BOTH, expand=True)
        
        # 日志文本框和滚动条
        text_frame = ttk.Frame(log_frame)
        text_frame.pack(fill=BOTH, expand=True)
        
        # 添加日志过滤按钮
        log_filter_frame = ttk.Frame(text_frame)
        log_filter_frame.pack(fill=X, pady=(0, 5))
        
        ttk.Button(
            log_filter_frame, 
            text="全部日志", 
            command=lambda: self.filter_logs("all"),
            style="Outline.TButton",
            width=10
        ).pack(side=LEFT, padx=2)
        
        ttk.Button(
            log_filter_frame, 
            text="仅显示威胁", 
            command=lambda: self.filter_logs("threats"),
            style="Outline.TButton",
            width=10
        ).pack(side=LEFT, padx=2)
        
        ttk.Button(
            log_filter_frame, 
            text="清空日志", 
            command=self.clear_logs,
            style="Outline.TButton",
            width=10
        ).pack(side=LEFT, padx=2)
        
        # 日志文本区域
        log_text_frame = ttk.Frame(text_frame)
        log_text_frame.pack(fill=BOTH, expand=True)
        
        # 获取ttk主题的背景色
        style = ttk.Style()
        bg_color = style.lookup('TFrame', 'background')
        
        self.text_box = tk.Text(
            log_text_frame, 
            state=tk.DISABLED,
            font=default_font,
            wrap=tk.WORD,
            relief=FLAT,
            bg=bg_color,
            fg="#eee"
        )
        self.text_box.pack(side=LEFT, fill=BOTH, expand=True)
        
        # 添加水平滚动条
        y_scrollbar = ttk.Scrollbar(log_text_frame, command=self.text_box.yview)
        y_scrollbar.pack(side=RIGHT, fill=Y)
        
        x_scrollbar = ttk.Scrollbar(text_frame, orient=HORIZONTAL, command=self.text_box.xview)
        x_scrollbar.pack(side=BOTTOM, fill=X)
        
        self.text_box.config(yscrollcommand=y_scrollbar.set, xscrollcommand=x_scrollbar.set)
        
        # 存储完整日志用于过滤
        self.full_log = []

    def filter_logs(self, filter_type):
        """过滤日志显示"""
        # 保存当前过滤模式
        self.current_log_filter = filter_type
        
        self.text_box.config(state=tk.NORMAL)
        self.text_box.delete('1.0', tk.END)
        
        if filter_type == "all":
            # 显示所有日志
            for msg in self.full_log:
                self.text_box.insert(tk.END, msg + "\n\n")
        elif filter_type == "threats":
            # 只显示威胁相关日志，扩展关键词以确保捕获所有威胁
            threat_keywords = ["⚠", "病毒", "风险", "恶意", "可疑", "广告风险", "启发式扫描发现"]
            for msg in self.full_log:
                if any(keyword in msg for keyword in threat_keywords):
                    self.text_box.insert(tk.END, msg + "\n\n")
                    
        self.text_box.see(tk.END)
        self.text_box.config(state=tk.DISABLED)

    def clear_logs(self):
        """清空日志"""
        self.text_box.config(state=tk.NORMAL)
        self.text_box.delete('1.0', tk.END)
        self.text_box.config(state=tk.DISABLED)
        self.full_log = []
        # 重置过滤模式为全部
        self.current_log_filter = 'all'

    def check_database_status(self):
        """检查并显示数据库加载状态"""
        # 病毒库状态
        if self.virus_db_loaded and len(self.virus_db) > 0:
            self.virus_db_status.config(
                text="病毒库(zhuzhu009)：正常",
                foreground="#4CAF50"  # 绿色表示正常
            )
        else:
            self.virus_db_status.config(
                text="病毒库(zhuzhu009)：异常！请检查文件",
                foreground="#f44336"  # 红色表示错误
            )
            messagebox.showerror("数据库错误", "病毒库加载失败，请检查文件是否存在且格式正确")
        
        # 广告库状态
        if self.ad_db_loaded and len(self.ad_db) > 0:
            self.ad_db_status.config(
                text="广告库(zhuzhu009)：正常",
                foreground="#4CAF50"  # 绿色表示正常
            )
        else:
            self.ad_db_status.config(
                text="广告库(zhuzhu009)：未加载或为空",
                foreground="#ff9800"  # 橙色表示警告
            )

    def start_scan(self):
        """开始扫描"""
        global is_scanning, stop_scanning
        stop_scanning = False
        if is_scanning:
            return
            
        # 检查病毒库是否加载成功
        if not self.virus_db_loaded or len(self.virus_db) == 0:
            messagebox.showwarning("警告", "病毒库加载失败，扫描功能可能受限")
        
        folder = self.folder_path.get().strip()
        files = [f.strip() for f in self.file_path.get().split(';') if f.strip()]
        
        if not folder and not files:
            messagebox.showwarning("提示", "请选择文件或目录")
            return
        
        # 禁用开始扫描按钮
        self.btn_scan.config(state=DISABLED)
        
        # 加载启发式规则
        batched_rules = []
        if self.heuristic_enabled.get():
            batched_rules, rule_count = load_heuristic_rules()
            if rule_count == 0:
                messagebox.showwarning("警告", "未加载任何启发式规则，启发式扫描功能不可用")
        
        is_scanning = True
        self.update_status_label()

        # 启动扫描线程
        if folder:
            threading.Thread(
                target=scan_directory,
                args=(folder, self.virus_db, self.whitelist, self.ad_db, batched_rules, self),
                daemon=True
            ).start()
        else:
            threading.Thread(
                target=scan_files,
                args=(files, self.virus_db, self.whitelist, self.ad_db, batched_rules, self),
                daemon=True
            ).start()

    def pause_scan(self):
        """暂停/继续扫描"""
        global pause_scanning
        pause_scanning = not pause_scanning
        self.btn_pause.config(
            text="继续扫描", 
            style="Success.TButton" if pause_scanning else "Warning.TButton"
        )
        log("扫描已暂停" if pause_scanning else "扫描已继续")

    def stop_scan(self):
        """停止扫描"""
        global is_scanning, stop_scanning
        is_scanning = False
        stop_scanning = True
        self.update_status_label()
        log("扫描已停止")
        self.btn_scan.config(state=NORMAL)

    def delete_virus_files(self):
        """删除检测到的病毒文件"""
        with self.lock_detected_files:
            files = self.detected_virus_files.copy()
        
        if not files:
            messagebox.showinfo("提示", "没有检测到病毒文件")
            return
            
        confirm = messagebox.askyesno(
            "确认删除", 
            f"确定要删除这 {len(files)} 个病毒文件吗？\n此操作不可恢复！"
        )
        
        if not confirm:
            return
            
        deleted = 0
        for f in files:
            try:
                if os.path.exists(f):
                    os.remove(f)
                    self.detected_virus_files.remove(f)
                    deleted += 1
                    log(f"已删除病毒文件: {f}")
            except Exception as e:
                log(f"删除失败: {f} - {str(e)}")
        
        log(f"共删除{deleted}/{len(files)}个病毒文件")
        messagebox.showinfo("操作完成", f"共删除{deleted}/{len(files)}个病毒文件")

    def delete_ad_files(self):
        """删除检测到的广告文件"""
        with self.lock_detected_ad_files:
            files = self.detected_ad_files.copy()
        
        if not files:
            messagebox.showinfo("提示", "没有检测到广告文件")
            return
            
        confirm = messagebox.askyesno(
            "确认删除", 
            f"确定要删除这 {len(files)} 个广告文件吗？\n此操作不可恢复！"
        )
        
        if not confirm:
            return
            
        deleted = 0
        for f in files:
            try:
                if os.path.exists(f):
                    os.remove(f)
                    self.detected_ad_files.remove(f)
                    deleted += 1
                    log(f"已删除广告文件: {f}")
            except Exception as e:
                log(f"删除失败: {f} - {str(e)}")
        
        log(f"共删除{deleted}/{len(files)}个广告文件")
        messagebox.showinfo("操作完成", f"共删除{deleted}/{len(files)}个广告文件")

    def update_status_label(self):
        """更新扫描状态标签"""
        global is_scanning
        if is_scanning:
            self.status_var.set(
                f"扫描中... 总文件: {total_scanned_files}  "
                f"已扫描: {scanned_files_count}  "
                f"发现病毒: {len(self.detected_virus_files)}  "
                f"发现广告: {len(self.detected_ad_files)}"
            )
        else:
            self.status_var.set(
                f"就绪 | 总文件: {total_scanned_files}  "
                f"已扫描: {scanned_files_count}  "
                f"发现病毒: {len(self.detected_virus_files)}  "
                f"发现广告: {len(self.detected_ad_files)}"
            )
        self.root.after(1000, self.update_status_label)

    def update_scan_progress(self):
        """更新扫描进度条"""
        global total_scanned_files, scanned_files_count
        if total_scanned_files > 0:
            progress = (scanned_files_count / total_scanned_files) * 100
            self.scan_progress_var.set(progress)
            self.progress_label.config(text=f"{int(progress)}%")

    def update_current_file_label(self, text):
        """更新当前扫描文件标签"""
        if len(text) > 70:
            text = text[:70] + "..."
        self.current_file_var.set(text)

    def check_cloud_connectivity(self):
        """检查云连接状态"""
        def check():
            try:
                requests.get("https://www.filescan.io", timeout=3)
                self.cloud_status.set("云查杀连接正常")
            except Exception:
                self.cloud_status.set("云查杀连接失败")
        threading.Thread(target=check, daemon=True).start()
        self.root.after(60000, self.check_cloud_connectivity)

    def quit_app(self):
        """退出程序"""
        if is_scanning:
            if messagebox.askyesno("确认退出", "扫描正在进行中，确定要退出吗？"):
                self.root.destroy()
                sys.exit(0)
        else:
            self.root.destroy()
            sys.exit(0)

    def run(self):
        """运行主循环"""
        self.root.mainloop()


if __name__ == "__main__":
    # 单实例检查
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(('127.0.0.1', INSTANCE_PORT))
    except socket.error:
        messagebox.showinfo("提示", "程序已在运行")
        sys.exit(0)
    
    app = VirusScanApp()
    app.run()
