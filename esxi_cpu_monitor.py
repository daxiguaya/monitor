#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import json
import csv
import ssl
import signal
import socket
import getpass
import datetime
import urllib.request
import urllib.error
import xml.etree.ElementTree as ET

# ============================================================
# 配置
# ============================================================

BASE_DIR = "/volume1/homes/willadmin/esxi-monitor"

CSV_FILE = os.path.join(BASE_DIR, "esxi_cpu_monitor.csv")
RUN_LOG = os.path.join(BASE_DIR, "esxi_cpu_monitor.log")
STATE_FILE = os.path.join(BASE_DIR, "esxi_cpu_monitor_state.json")

PID_FILE = "/tmp/esxi_cpu_monitor.pid"

# 旧 V1 数据
LEGACY_CSV_FILE = "/tmp/esxi_cpu_monitor.csv"

ESXI_HOST = "192.168.5.100"
ESXI_USER = "root"
ESXI_PORT = 443
SOAP_URL = "https://{}:{}/sdk".format(ESXI_HOST, ESXI_PORT)

INTERVAL = 60

# 动态基线
BASELINE_HOURS = 24
MAX_HISTORY = 1560

# 异常判定
HIGH_RATIO = 2.0
MIN_BASELINE_MHZ = 100
HOST_CRITICAL_PERCENT = 30.0

# 持续时间
HIGH_SECONDS = 15 * 60
CRITICAL_SECONDS = 60 * 60
LONG_HIGH_SECONDS = 5 * 60 * 60

# 恢复
RECOVERY_RATIO = 1.5

# VM 顺序
VM_ORDER = [
    "OpenWRT",
    "Win11",
    "Palworld",
    "DSM7.2",
]


# ============================================================
# 全局
# ============================================================

running = True
password = None


# ============================================================
# 基础工具
# ============================================================

def now_string():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def ensure_base_dir():
    if not os.path.isdir(BASE_DIR):
        os.makedirs(BASE_DIR)


def log(message):
    line = "[{}] {}".format(now_string(), message)

    try:
        print(line, flush=True)
    except Exception:
        pass

    try:
        with open(RUN_LOG, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


def write_pid():
    with open(PID_FILE, "w") as f:
        f.write(str(os.getpid()))


def remove_pid():
    try:
        if os.path.exists(PID_FILE):
            with open(PID_FILE, "r") as f:
                pid = f.read().strip()

            if pid == str(os.getpid()):
                os.remove(PID_FILE)
    except Exception:
        pass


def process_cmdline(pid):
    try:
        with open("/proc/{}/cmdline".format(pid), "rb") as f:
            data = f.read()
        return data.replace(b"\x00", b" ").decode("utf-8", "ignore")
    except Exception:
        return ""


def is_process_running(pid):
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def check_existing_process():
    if not os.path.exists(PID_FILE):
        return False

    try:
        with open(PID_FILE, "r") as f:
            pid_text = f.read().strip()

        if not pid_text:
            os.remove(PID_FILE)
            return False

        pid = int(pid_text)

        if not is_process_running(pid):
            os.remove(PID_FILE)
            return False

        cmdline = process_cmdline(pid)

        current_script = os.path.abspath(__file__)

        # 只有确认是当前 V2 脚本才认为正在运行
        if current_script in cmdline:
            print("监控已经在运行 PID: {}".format(pid))
            return True

        # 旧 V1 / 其他进程占用了旧 PID 文件
        print("发现旧 PID 文件，但对应进程不是当前 V2。")
        print("PID: {}".format(pid))
        print("CMD: {}".format(cmdline))
        print("清理旧 PID 文件，继续启动 V2。")

        os.remove(PID_FILE)

    except Exception as e:
        print("检查 PID 文件失败: {}".format(e))

        try:
            os.remove(PID_FILE)
        except Exception:
            pass

    return False


# ============================================================
# XML / SOAP
# ============================================================

SOAP_ENV = "http://schemas.xmlsoap.org/soap/envelope/"
VIM25 = "urn:vim25"


def soap_request(session_cookie, body):
    envelope = """<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope
    xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
    xmlns:vim25="urn:vim25">
    <soapenv:Body>
        {}
    </soapenv:Body>
</soapenv:Envelope>""".format(body)

    req = urllib.request.Request(
        SOAP_URL,
        data=envelope.encode("utf-8"),
        headers={
            "Content-Type": "text/xml; charset=utf-8",
            "SOAPAction": "",
            "Cookie": session_cookie,
        },
        method="POST",
    )

    context = ssl._create_unverified_context()

    with urllib.request.urlopen(
        req,
        context=context,
        timeout=30,
    ) as response:
        return response.read()


def get_tag(element):
    if "}" in element.tag:
        return element.tag.split("}", 1)[1]
    return element.tag


def find_first_text(root, tag_name):
    for element in root.iter():
        if get_tag(element) == tag_name:
            if element.text:
                return element.text.strip()
    return None


# ============================================================
# ESXi 登录
# ============================================================

def esxi_login():
    body = """
<vim25:Login>
    <vim25:_this type="SessionManager">ha-sessionmgr</vim25:_this>
    <vim25:userName>{}</vim25:userName>
    <vim25:password>{}</vim25:password>
</vim25:Login>
""".format(
        escape_xml(ESXI_USER),
        escape_xml(password),
    )

    try:
        data = soap_request("", body)
        root = ET.fromstring(data)

        fault = None
        for element in root.iter():
            if get_tag(element) == "Fault":
                fault = element
                break

        if fault is not None:
            print("ESXi 登录失败")
            return None

        cookie = None

        # urllib 的 Cookie 不能直接从 response 得到，因为这里使用
        # urlopen 后已经关闭。重新通过 Login API 不方便获取 cookie。
        #
        # 因此这里采用 SessionManager 的 cookie 模式：
        # vCenter/ESXi 通常返回 Set-Cookie vmware_soap_session。
        #
        # 为兼容 NAS Python 3.8，改用自定义 opener 重新登录。

        return login_with_opener()

    except Exception as e:
        print("ESXi 登录失败: {}".format(e))
        return None


class CookieCollector(urllib.request.HTTPRedirectHandler):
    pass


def login_with_opener():
    import http.cookiejar

    cj = http.cookiejar.CookieJar()

    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(cj)
    )

    body = """<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope
    xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
    xmlns:vim25="urn:vim25">
    <soapenv:Body>
        <vim25:Login>
            <vim25:_this type="SessionManager">ha-sessionmgr</vim25:_this>
            <vim25:userName>{}</vim25:userName>
            <vim25:password>{}</vim25:password>
        </vim25:Login>
    </soapenv:Body>
</soapenv:Envelope>
""".format(
        escape_xml(ESXI_USER),
        escape_xml(password),
    )

    req = urllib.request.Request(
        SOAP_URL,
        data=body.encode("utf-8"),
        headers={
            "Content-Type": "text/xml; charset=utf-8",
            "SOAPAction": "",
        },
        method="POST",
    )

    context = ssl._create_unverified_context()

    try:
        response = opener.open(req, timeout=30, context=context)
    except TypeError:
        # Python 3.8 某些 urllib opener 不接受 context 参数
        opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(cj),
            urllib.request.HTTPSHandler(context=context),
        )
        response = opener.open(req, timeout=30)

    data = response.read()

    root = ET.fromstring(data)

    for element in root.iter():
        if get_tag(element) == "Fault":
            return None

    cookies = []

    for cookie in cj:
        cookies.append("{}={}".format(cookie.name, cookie.value))

    if not cookies:
        return None

    return ESXiSession(opener, context, cookies)


class ESXiSession:
    def __init__(self, opener, context, cookies):
        self.opener = opener
        self.context = context
        self.cookie_header = "; ".join(cookies)

    def request(self, body):
        envelope = """<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope
    xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
    xmlns:vim25="urn:vim25">
    <soapenv:Body>
        {}
    </soapenv:Body>
</soapenv:Envelope>""".format(body)

        req = urllib.request.Request(
            SOAP_URL,
            data=envelope.encode("utf-8"),
            headers={
                "Content-Type": "text/xml; charset=utf-8",
                "SOAPAction": "",
                "Cookie": self.cookie_header,
            },
            method="POST",
        )

        try:
            response = self.opener.open(req, timeout=30)
        except TypeError:
            response = self.opener.open(req, timeout=30)

        return response.read()


def escape_xml(value):
    return (
        str(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )


# ============================================================
# ESXi VM 发现
# ============================================================

def discover_vms(session):
    body = """
<vim25:RetrieveProperties>
    <vim25:_this type="PropertyCollector">ha-property-collector</vim25:_this>
    <vim25:specSet>
        <vim25:propSet>
            <vim25:type>VirtualMachine</vim25:type>
            <vim25:pathSet>name</vim25:pathSet>
        </vim25:propSet>
        <vim25:objectSet>
            <vim25:obj type="Folder">ha-folder-root</vim25:obj>
            <vim25:selectSet xsi:type="vim25:TraversalSpec"
                xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <vim25:name>visitFolders</vim25:name>
                <vim25:type>Folder</vim25:type>
                <vim25:path>childEntity</vim25:path>
                <vim25:skip>false</vim25:skip>
                <vim25:selectSet xsi:type="vim25:SelectionSpec">
                    <vim25:name>visitFolders</vim25:name>
                </vim25:selectSet>
                <vim25:selectSet>
                    <vim25:name>dcToVm</vim25:name>
                </vim25:selectSet>
            </vim25:selectSet>
            <vim25:selectSet xsi:type="vim25:TraversalSpec"
                xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <vim25:name>dcToVm</vim25:name>
                <vim25:type>Datacenter</vim25:type>
                <vim25:path>vmFolder</vim25:path>
                <vim25:skip>false</vim25:skip>
                <vim25:selectSet>
                    <vim25:name>visitFolders</vim25:name>
                </vim25:selectSet>
            </vim25:selectSet>
        </vim25:objectSet>
    </vim25:specSet>
</vim25:RetrieveProperties>
"""

    try:
        data = session.request(body)
        root = ET.fromstring(data)

        vms = {}

        current_obj = None
        current_name = None

        for element in root.iter():
            tag = get_tag(element)

            if tag == "obj":
                current_obj = element.text
                current_name = None

                if element.attrib.get("type") != "VirtualMachine":
                    current_obj = None

            elif tag == "val" and current_obj:
                if current_name is None:
                    current_name = element.text

            elif tag == "propSet" and current_obj:
                pass

        # 更可靠地逐个解析 ObjectContent
        vms = {}

        for obj_content in root.iter():
            if get_tag(obj_content) != "ObjectContent":
                continue

            obj_id = None
            vm_name = None

            for child in obj_content:
                tag = get_tag(child)

                if tag == "obj":
                    obj_id = child.text
                    if child.attrib.get("type") != "VirtualMachine":
                        obj_id = None

                elif tag == "propSet":
                    for prop in child.iter():
                        if get_tag(prop) == "val":
                            vm_name = prop.text
                            break

            if obj_id and vm_name:
                vms[vm_name] = obj_id

        # 如果上面没有解析出来，使用通用方法再次解析
        if not vms:
            current_obj = None

            for element in root.iter():
                tag = get_tag(element)

                if tag == "obj":
                    if element.attrib.get("type") == "VirtualMachine":
                        current_obj = element.text
                    else:
                        current_obj = None

                elif tag == "val" and current_obj:
                    if element.text:
                        vms[element.text] = current_obj
                        current_obj = None

        return vms

    except Exception as e:
        log("VM 发现失败: {}".format(e))
        return {}


# ============================================================
# 获取 ESXi Host CPU 信息
# ============================================================

def get_host_cpu(session):
    body = """
<vim25:RetrieveProperties>
    <vim25:_this type="PropertyCollector">ha-property-collector</vim25:_this>
    <vim25:specSet>
        <vim25:propSet>
            <vim25:type>HostSystem</vim25:type>
            <vim25:pathSet>summary.hardware.cpuMhz</vim25:pathSet>
            <vim25:pathSet>summary.hardware.numCpuCores</vim25:pathSet>
            <vim25:pathSet>summary.quickStats.overallCpuUsage</vim25:pathSet>
        </vim25:propSet>
        <vim25:objectSet>
            <vim25:obj type="HostSystem">ha-host</vim25:obj>
        </vim25:objectSet>
    </vim25:specSet>
</vim25:RetrieveProperties>
"""

    try:
        data = session.request(body)
        root = ET.fromstring(data)

        values = []

        for element in root.iter():
            if get_tag(element) == "val":
                if element.text is not None:
                    values.append(element.text.strip())

        if len(values) < 3:
            log("Host CPU 返回数据不足: {}".format(values))
            return None

        cpu_mhz = None
        cores = None
        usage = None

        for value in values:
            try:
                number = float(value)

                if cpu_mhz is None:
                    cpu_mhz = number
                elif cores is None:
                    cores = number
                elif usage is None:
                    usage = number

            except Exception:
                continue

        if cpu_mhz is None or cores is None or usage is None:
            log("Host CPU 数值解析失败: {}".format(values))
            return None

        capacity = cpu_mhz * cores

        return {
            "cpu_mhz": usage,
            "capacity_mhz": capacity,
            "percent": (
                usage / capacity * 100.0
                if capacity > 0
                else 0.0
            ),
        }

    except Exception as e:
        log("获取 Host CPU 失败: {}".format(e))
        return None


# ============================================================
# 获取 VM CPU
# ============================================================

def get_vm_cpu(session, vms):
    result = {}

    for name, vm_id in vms.items():

        body = """
<vim25:RetrieveProperties>
    <vim25:_this type="PropertyCollector">ha-property-collector</vim25:_this>
    <vim25:specSet>
        <vim25:propSet>
            <vim25:type>VirtualMachine</vim25:type>
            <vim25:pathSet>name</vim25:pathSet>
            <vim25:pathSet>summary.quickStats.overallCpuUsage</vim25:pathSet>
            <vim25:pathSet>runtime.powerState</vim25:pathSet>
        </vim25:propSet>
        <vim25:objectSet>
            <vim25:obj type="VirtualMachine">{}</vim25:obj>
        </vim25:objectSet>
    </vim25:specSet>
</vim25:RetrieveProperties>
""".format(escape_xml(vm_id))

        try:
            data = session.request(body)
            root = ET.fromstring(data)

            vals = []

            for element in root.iter():
                if get_tag(element) == "val":
                    if element.text is not None:
                        vals.append(element.text.strip())

            cpu_usage = None
            power_state = None

            # val 顺序通常对应 name / CPU / powerState
            for value in vals:
                if value in (
                    "poweredOn",
                    "poweredOff",
                    "suspended",
                ):
                    power_state = value

            for value in vals:
                try:
                    number = float(value)
                    if number >= 0:
                        cpu_usage = number
                        break
                except Exception:
                    continue

            result[name] = {
                "cpu_mhz": cpu_usage if cpu_usage is not None else 0.0,
                "power_state": power_state or "unknown",
            }

        except Exception as e:
            log("获取 VM {} CPU 失败: {}".format(name, e))
            result[name] = {
                "cpu_mhz": 0.0,
                "power_state": "unknown",
            }

    return result


# ============================================================
# CSV
# ============================================================

CSV_HEADER = [
    "timestamp",
    "host_cpu_mhz",
    "OpenWRT",
    "Win11",
    "Palworld",
    "DSM7.2",
]


def csv_exists_and_valid():
    if not os.path.exists(CSV_FILE):
        return False

    try:
        if os.path.getsize(CSV_FILE) < 20:
            return False

        with open(CSV_FILE, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            header = next(reader)

        return "timestamp" in header and "host_cpu_mhz" in header

    except Exception:
        return False


def append_csv(timestamp, host_mhz, vm_values):
    file_exists = os.path.exists(CSV_FILE)

    with open(CSV_FILE, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=CSV_HEADER,
        )

        if not file_exists:
            writer.writeheader()

        row = {
            "timestamp": timestamp,
            "host_cpu_mhz": "{:.0f}".format(host_mhz),
            "OpenWRT": "",
            "Win11": "",
            "Palworld": "",
            "DSM7.2": "",
        }

        for name in VM_ORDER:
            if name in vm_values:
                value = vm_values[name]

                if value is not None:
                    row[name] = "{:.0f}".format(value)

        writer.writerow(row)


# ============================================================
# 历史数据
# ============================================================

def parse_timestamp(value):
    try:
        return datetime.datetime.strptime(
            value,
            "%Y-%m-%d %H:%M:%S",
        )
    except Exception:
        return None


def load_csv_history(path, target):
    history = []

    if not os.path.exists(path):
        return history

    try:
        with open(path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)

            for row in reader:
                timestamp = parse_timestamp(
                    row.get("timestamp", "")
                )

                if timestamp is None:
                    continue

                value = row.get(target, "")

                if value is None or value == "":
                    continue

                try:
                    value = float(value)
                except Exception:
                    continue

                history.append({
                    "timestamp": timestamp.timestamp(),
                    "value": value,
                })

    except Exception as e:
        log("读取历史 CSV 失败 {}: {}".format(path, e))

    return history


def load_all_history():
    history = {
        "Host": [],
        "OpenWRT": [],
        "Win11": [],
        "Palworld": [],
        "DSM7.2": [],
    }

    # --------------------------------------------------------
    # 优先读取新的持久 CSV
    # --------------------------------------------------------

    if csv_exists_and_valid():
        log("发现持久目录 V2 CSV: {}".format(CSV_FILE))

        history["Host"] = load_csv_history(
            CSV_FILE,
            "host_cpu_mhz",
        )

        for name in VM_ORDER:
            history[name] = load_csv_history(
                CSV_FILE,
                name,
            )

    else:
        log("持久目录没有 V2 CSV")

        # ----------------------------------------------------
        # 自动导入旧 V1 CSV
        # ----------------------------------------------------

        if os.path.exists(LEGACY_CSV_FILE):
            log("发现 /tmp 中的旧 V1 CSV: {}".format(
                LEGACY_CSV_FILE
            ))
            log("正在读取旧 V1 CSV")

            history["Host"] = load_csv_history(
                LEGACY_CSV_FILE,
                "host_cpu_mhz",
            )

            for name in VM_ORDER:
                history[name] = load_csv_history(
                    LEGACY_CSV_FILE,
                    name,
                )

            log("旧 V1 CSV 历史数据导入完成")
        else:
            log("没有找到旧 V1 CSV")

    # --------------------------------------------------------
    # 只保留最近 24 小时
    # --------------------------------------------------------

    cutoff = time.time() - BASELINE_HOURS * 3600

    for target in history:
        history[target] = [
            item
            for item in history[target]
            if item["timestamp"] >= cutoff
        ]

        history[target] = history[target][-MAX_HISTORY:]

    return history


# ============================================================
# 状态文件
# ============================================================

def default_state():
    return {
        "Host": {
            "status": "NORMAL",
            "abnormal_since": None,
        },
        "OpenWRT": {
            "status": "NORMAL",
            "abnormal_since": None,
        },
        "Win11": {
            "status": "NORMAL",
            "abnormal_since": None,
        },
        "Palworld": {
            "status": "NORMAL",
            "abnormal_since": None,
        },
        "DSM7.2": {
            "status": "NORMAL",
            "abnormal_since": None,
        },
    }


def load_state():
    if not os.path.exists(STATE_FILE):
        return default_state()

    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)

        state = default_state()

        for target in state:
            if target in data:
                if "status" in data[target]:
                    state[target]["status"] = data[target]["status"]

                if "abnormal_since" in data[target]:
                    state[target]["abnormal_since"] = data[target][
                        "abnormal_since"
                    ]

        return state

    except Exception as e:
        log("读取状态文件失败，重新初始化: {}".format(e))
        return default_state()


def save_state(state):
    tmp_file = STATE_FILE + ".tmp"

    try:
        with open(tmp_file, "w", encoding="utf-8") as f:
            json.dump(
                state,
                f,
                ensure_ascii=False,
                indent=2,
            )

        os.replace(tmp_file, STATE_FILE)

    except Exception as e:
        log("保存状态失败: {}".format(e))


# ============================================================
# 动态基线
# ============================================================

def calculate_baseline(history):
    if not history:
        return None

    cutoff = time.time() - BASELINE_HOURS * 3600

    values = [
        item["value"]
        for item in history
        if item["timestamp"] >= cutoff
    ]

    if not values:
        return None

    # 排除极端高值：
    # 用排序后中间 80% 的数据计算平均值
    # 避免一次大尖峰抬高 baseline
    values = sorted(values)

    if len(values) >= 10:
        low = int(len(values) * 0.10)
        high = int(len(values) * 0.90)

        trimmed = values[low:high]

        if trimmed:
            values = trimmed

    baseline = sum(values) / float(len(values))

    return baseline


def calculate_status(
    current,
    baseline,
    previous_status,
    abnormal_since,
    target=None,
    host_percent=None,
):
    if baseline is None:
        return (
            "OBSERVE",
            None,
            0.0,
        )

    effective_baseline = max(
        baseline,
        MIN_BASELINE_MHZ,
    )

    ratio = current / effective_baseline

    now = time.time()

    # --------------------------------------------------------
    # 正常 / 恢复
    #
    # <= 1.5x：正常
    # --------------------------------------------------------

    if ratio <= RECOVERY_RATIO:
        return (
            "NORMAL",
            None,
            ratio,
        )

    # --------------------------------------------------------
    # 1.5x ~ 2.0x：
    #
    # 只是观察，不开始异常计时。
    #
    # 这是根据两天真实数据调整后的核心逻辑。
    # --------------------------------------------------------

    if ratio < HIGH_RATIO:
        return (
            "OBSERVE",
            None,
            ratio,
        )

    # --------------------------------------------------------
    # Host 特殊规则
    #
    # Host >= 2.0x baseline，但是实际 CPU < 30%：
    #
    # 可以进入 HIGH，
    # 但不允许升级到 CRITICAL / LONG_HIGH。
    #
    # 这样可以避免：
    #
    # Host 220 MHz -> 450 MHz
    #
    # 这种对于 N100 实际只有约 14% 的正常工作状态，
    # 最终被判定成 CRITICAL。
    # --------------------------------------------------------

    host_low_load = (
        target == "Host"
        and host_percent is not None
        and host_percent < HOST_CRITICAL_PERCENT
    )

    # --------------------------------------------------------
    # 第一次进入真正异常区间
    # --------------------------------------------------------

    if abnormal_since is None:
        abnormal_since = now

    duration = now - abnormal_since

    # --------------------------------------------------------
    # 持续时间升级
    #
    # 15 分钟：
    #   HIGH
    #
    # 1 小时：
    #   CRITICAL
    #   但 Host 必须 >= 30%
    #
    # 5 小时：
    #   LONG_HIGH
    #   但 Host 必须 >= 30%
    # --------------------------------------------------------

    if duration >= LONG_HIGH_SECONDS:
        if host_low_load:
            status = "HIGH"
        else:
            status = "LONG_HIGH"

    elif duration >= CRITICAL_SECONDS:
        if host_low_load:
            status = "HIGH"
        else:
            status = "CRITICAL"

    elif duration >= HIGH_SECONDS:
        status = "HIGH"

    else:
        status = "OBSERVE"

    return (
        status,
        abnormal_since,
        ratio,
    )


# ============================================================
# 状态变化输出
# ============================================================

def print_status(
    target,
    current,
    baseline,
    ratio,
    status,
    previous_status,
):
    if baseline is None:
        baseline_text = "N/A"
    else:
        baseline_text = "{:.1f}".format(baseline)

    line = (
        "{}: {:.0f} MHz "
        "baseline={} "
        "ratio={:.2f}x "
        "status={}"
    ).format(
        target,
        current,
        baseline_text,
        ratio,
        status,
    )

    if status != previous_status:
        line += " [状态变化: {} -> {}]".format(
            previous_status,
            status,
        )

    log(line)


# ============================================================
# 历史样本追加
# ============================================================

def add_history(history, target, value):
    if value is None:
        return

    history[target].append({
        "timestamp": time.time(),
        "value": float(value),
    })

    cutoff = time.time() - BASELINE_HOURS * 3600

    history[target] = [
        item
        for item in history[target]
        if item["timestamp"] >= cutoff
    ]

    if len(history[target]) > MAX_HISTORY:
        history[target] = history[target][-MAX_HISTORY:]


# ============================================================
# 信号
# ============================================================

def signal_handler(signum, frame):
    global running

    log("收到退出信号 {}, 准备停止监控".format(signum))
    running = False


# ============================================================
# daemon
# ============================================================

def daemonize():
    pid = os.fork()

    if pid > 0:
        # 父进程正常退出
        print("监控已转入后台")
        print("后台 PID: {}".format(pid))
        return False

    # 子进程脱离当前终端
    os.setsid()

    # daemon 后：
    # stdout 不再重定向到 RUN_LOG。
    # log() 本身已经同时负责终端输出和写入 RUN_LOG，
    # 如果 stdout 也指向 RUN_LOG，会造成每条日志重复一次。
    try:
        stdin = open(os.devnull, "r")
        stdout = open(os.devnull, "w")
        stderr = open(RUN_LOG, "a", buffering=1)

        os.dup2(stdin.fileno(), 0)
        os.dup2(stdout.fileno(), 1)
        os.dup2(stderr.fileno(), 2)

        stdin.close()
        stdout.close()

    except Exception:
        pass

    return True


# ============================================================
# 主监控循环
# ============================================================

def monitor(session, vms, history, state):
    global running

    write_pid()

    log("=" * 60)
    log("ESXi CPU Monitor V2 后台监控启动")
    log("ESXi: {}".format(ESXI_HOST))
    log("采样间隔: {} 秒".format(INTERVAL))
    log("动态基线: 最近 {} 小时".format(BASELINE_HOURS))
    log("OBSERVE: {:.1f}x ~ {:.1f}x".format(
        RECOVERY_RATIO,
        HIGH_RATIO,
    ))
    log("HIGH: {:.1f}x + {} 分钟".format(
        HIGH_RATIO,
        HIGH_SECONDS // 60,
    ))
    log("CRITICAL: {:.1f}x + {} 分钟 + Host >= {:.0f}%".format(
        HIGH_RATIO,
        CRITICAL_SECONDS // 60,
        HOST_CRITICAL_PERCENT,
    ))
    log("LONG_HIGH: {:.1f}x + {} 小时 + Host >= {:.0f}%".format(
        HIGH_RATIO,
        LONG_HIGH_SECONDS // 3600,
        HOST_CRITICAL_PERCENT,
    ))
    log("=" * 60)

    while running:

        cycle_start = time.time()

        try:
            host = get_host_cpu(session)

            if host is None:
                log("Host CPU 获取失败，本轮跳过")
                time.sleep(INTERVAL)
                continue

            vm_data = get_vm_cpu(session, vms)

            timestamp = now_string()

            vm_values = {}

            for name in VM_ORDER:
                if name in vm_data:
                    value = vm_data[name]["cpu_mhz"]

                    if (
                        vm_data[name]["power_state"] == "poweredOn"
                    ):
                        vm_values[name] = value
                    else:
                        vm_values[name] = None

            append_csv(
                timestamp,
                host["cpu_mhz"],
                vm_values,
            )

            # ------------------------------------------------
            # 计算 Host
            # ------------------------------------------------

            targets = {
                "Host": host["cpu_mhz"],
            }

            for name in VM_ORDER:
                if name in vm_values:
                    if vm_values[name] is not None:
                        targets[name] = vm_values[name]

            # ------------------------------------------------
            # 逐个目标判断
            # ------------------------------------------------

            for target, current in targets.items():

                baseline = calculate_baseline(
                    history[target]
                )

                previous_status = state[target]["status"]
                previous_abnormal_since = state[target][
                    "abnormal_since"
                ]

                status, abnormal_since, ratio = calculate_status(
                    current,
                    baseline,
                    previous_status,
                    previous_abnormal_since,
                    target=target,
                    host_percent=(
                        host["percent"]
                        if target == "Host"
                        else None
                    ),
                )

                state[target]["status"] = status
                state[target]["abnormal_since"] = abnormal_since

                print_status(
                    target,
                    current,
                    baseline,
                    ratio,
                    status,
                    previous_status,
                )

                # ------------------------------------------------
                # 只有 NORMAL 才进入动态基线
                #
                # OBSERVE/HIGH/CRITICAL/LONG_HIGH 不加入
                # 防止异常高负载把 baseline 抬高
                # ------------------------------------------------

                if status == "NORMAL":
                    add_history(
                        history,
                        target,
                        current,
                    )

            save_state(state)

            # ------------------------------------------------
            # 汇总
            # ------------------------------------------------

            log(
                "Host CPU: {:.0f} MHz ({:.1f}% / {:.0f} MHz)".format(
                    host["cpu_mhz"],
                    host["percent"],
                    host["capacity_mhz"],
                )
            )

            elapsed = time.time() - cycle_start

            sleep_seconds = max(
                1,
                INTERVAL - int(elapsed),
            )

            time.sleep(sleep_seconds)

        except KeyboardInterrupt:
            running = False

        except Exception as e:
            log("监控循环异常: {}".format(e))
            time.sleep(INTERVAL)

    remove_pid()
    log("ESXi CPU Monitor V2 已停止")


# ============================================================
# 启动
# ============================================================

def main():
    global password

    ensure_base_dir()

    print("")
    print("==============================================")
    print("ESXi CPU Monitor V2")
    print("动态基线 + 持续时间")
    print("==============================================")
    print("ESXi: {}".format(ESXI_HOST))
    print("持久目录: {}".format(BASE_DIR))
    print("CSV: {}".format(CSV_FILE))
    print("日志: {}".format(RUN_LOG))
    print("状态: {}".format(STATE_FILE))
    print("")

    if check_existing_process():
        return

    # --------------------------------------------------------
    # 加载历史
    # --------------------------------------------------------

    history = load_all_history()

    print("")
    print("历史 Host 样本: {}".format(
        len(history["Host"])
    ))

    for name in VM_ORDER:
        print(
            "历史 {:<10} 样本: {}".format(
                name,
                len(history[name]),
            )
        )

    # --------------------------------------------------------
    # 先展示当前基线
    # --------------------------------------------------------

    print("")
    print("当前历史基线:")

    for target in ["Host"] + VM_ORDER:
        baseline = calculate_baseline(
            history[target]
        )

        if baseline is None:
            print(
                "  {:<10} baseline=N/A".format(
                    target
                )
            )
        else:
            print(
                "  {:<10} baseline={:.1f} MHz".format(
                    target,
                    baseline,
                )
            )

    print("")

    # --------------------------------------------------------
    # 密码
    # --------------------------------------------------------

    password = getpass.getpass("ESXi root password: ")

    print("")
    print("正在登录 ESXi...")

    session = login_with_opener()

    if session is None:
        print("ESXi 登录失败，请检查密码或 ESXi HTTPS。")
        return

    print("ESXi 登录成功")

    # --------------------------------------------------------
    # VM 发现
    # --------------------------------------------------------

    print("正在发现 VM...")

    vms = discover_vms(session)

    if not vms:
        print("VM 发现失败")
        return

    print("发现 VM:")

    for name in VM_ORDER:
        if name in vms:
            print(
                "  {:<20} ID={}".format(
                    name,
                    vms[name],
                )
            )

    print("")
    print("VM 发现成功")

    # --------------------------------------------------------
    # 加载状态
    # --------------------------------------------------------

    state = load_state()

    # --------------------------------------------------------
    # 注册信号
    # --------------------------------------------------------

    signal.signal(
        signal.SIGTERM,
        signal_handler,
    )

    signal.signal(
        signal.SIGINT,
        signal_handler,
    )

    # --------------------------------------------------------
    # 后台运行
    # --------------------------------------------------------

    is_child = daemonize()

    if not is_child:
        # 父进程结束
        return

    monitor(
        session,
        vms,
        history,
        state,
    )


if __name__ == "__main__":
    main()
