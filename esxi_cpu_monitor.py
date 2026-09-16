cat > /tmp/esxi_cpu_monitor.py <<'PY'
#!/usr/bin/env python3

import csv
import getpass
import os
import sys
import time
import urllib3
import requests
import xml.etree.ElementTree as ET
from datetime import datetime

urllib3.disable_warnings(
    urllib3.exceptions.InsecureRequestWarning
)

ESXI_HOST = "192.168.5.100"
ESXI_USER = "root"
ESXI_URL = "https://%s/sdk" % ESXI_HOST

INTERVAL = 60

LOG_FILE = "/tmp/esxi_cpu_monitor.csv"
RUN_LOG = "/tmp/esxi_cpu_monitor.log"
PID_FILE = "/tmp/esxi_cpu_monitor.pid"

NS = {
    "vim": "urn:vim25",
}


def soap_request(session, body):

    envelope = """<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope
 xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
 xmlns:vim="urn:vim25">
 <soapenv:Body>
%s
 </soapenv:Body>
</soapenv:Envelope>
""" % body

    response = session.post(
        ESXI_URL,
        data=envelope.encode("utf-8"),
        headers={
            "Content-Type": "text/xml; charset=utf-8",
            "SOAPAction": ""
        },
        verify=False,
        timeout=30
    )

    if response.status_code != 200:

        print(
            "SOAP HTTP错误:",
            response.status_code
        )

        print(response.text[:2000])

        return None

    return ET.fromstring(
        response.content
    )


def login():

    password = getpass.getpass(
        "ESXi root password: "
    )

    session = requests.Session()
    session.verify = False

    body = """
  <vim:RetrieveServiceContent>
   <vim:_this type="ServiceInstance">ServiceInstance</vim:_this>
  </vim:RetrieveServiceContent>
"""

    root = soap_request(
        session,
        body
    )

    if root is None:
        raise RuntimeError(
            "无法连接 ESXi"
        )

    session_manager = root.find(
        ".//vim:sessionManager",
        NS
    )

    if session_manager is None:
        raise RuntimeError(
            "找不到 sessionManager"
        )

    session_manager_id = session_manager.text.strip()

    print(
        "sessionManager:",
        session_manager_id
    )

    body = """
  <vim:Login>
   <vim:_this type="SessionManager">%s</vim:_this>
   <vim:userName>%s</vim:userName>
   <vim:password>%s</vim:password>
  </vim:Login>
""" % (
        session_manager_id,
        ESXI_USER,
        password
    )

    root = soap_request(
        session,
        body
    )

    if root is None:
        raise RuntimeError(
            "ESXi 登录失败"
        )

    if not any(
        c.name == "vmware_soap_session"
        for c in session.cookies
    ):
        raise RuntimeError(
            "没有取得 vmware_soap_session"
        )

    print("登录成功")

    # 删除密码变量
    password = None

    return session


def retrieve_properties(
    session,
    obj_type,
    obj_id,
    properties
):

    prop_set = ""

    for prop in properties:

        prop_set += """
   <vim:propSet>
    <vim:type>%s</vim:type>
    <vim:all>false</vim:all>
    <vim:pathSet>%s</vim:pathSet>
   </vim:propSet>
""" % (
            obj_type,
            prop
        )

    body = """
  <vim:RetrieveProperties>
   <vim:_this type="PropertyCollector">ha-property-collector</vim:_this>

   <vim:specSet>
%s
    <vim:objectSet>
     <vim:obj type="%s">%s</vim:obj>
     <vim:skip>false</vim:skip>
    </vim:objectSet>
   </vim:specSet>

  </vim:RetrieveProperties>
""" % (
        prop_set,
        obj_type,
        obj_id
    )

    return soap_request(
        session,
        body
    )


def parse_properties(root):

    result = {}

    if root is None:
        return result

    for prop in root.findall(
        ".//vim:propSet",
        NS
    ):

        name = prop.find(
            "vim:name",
            NS
        )

        value = prop.find(
            "vim:val",
            NS
        )

        if (
            name is not None
            and value is not None
        ):

            result[name.text] = value

    return result


def discover_vms(session):

    root = retrieve_properties(
        session,
        "Folder",
        "ha-folder-vm",
        ["childEntity"]
    )

    if root is None:
        raise RuntimeError(
            "无法读取 VM Folder"
        )

    vms = []

    for mor in root.findall(
        ".//vim:ManagedObjectReference",
        NS
    ):

        if mor.attrib.get(
            "type"
        ) != "VirtualMachine":

            continue

        vm_id = mor.text.strip()

        vms.append({
            "id": vm_id,
            "name": vm_id
        })

    for vm in vms:

        root = retrieve_properties(
            session,
            "VirtualMachine",
            vm["id"],
            ["name"]
        )

        props = parse_properties(
            root
        )

        value = props.get(
            "name"
        )

        if value is not None:
            vm["name"] = value.text

    return vms


def get_vm_cpu(
    session,
    vm
):

    root = retrieve_properties(
        session,
        "VirtualMachine",
        vm["id"],
        [
            "runtime.powerState",
            "summary.quickStats.overallCpuUsage"
        ]
    )

    props = parse_properties(
        root
    )

    power = props.get(
        "runtime.powerState"
    )

    if power is None:
        return None

    if power.text != "poweredOn":
        return None

    cpu = props.get(
        "summary.quickStats.overallCpuUsage"
    )

    if cpu is None:
        return 0

    try:
        return int(cpu.text)
    except:
        return 0


def get_host_cpu(session):

    root = retrieve_properties(
        session,
        "HostSystem",
        "ha-host",
        [
            "summary.runtime.powerState",
            "summary.quickStats.overallCpuUsage"
        ]
    )

    props = parse_properties(
        root
    )

    power = props.get(
        "summary.runtime.powerState"
    )

    if power is None:
        return None

    if power.text != "poweredOn":
        return None

    cpu = props.get(
        "summary.quickStats.overallCpuUsage"
    )

    if cpu is None:
        return None

    try:
        return int(cpu.text)
    except:
        return None


def init_csv(vms):

    if os.path.exists(
        LOG_FILE
    ):
        return

    fields = [
        "timestamp",
        "host_cpu_mhz"
    ]

    for vm in vms:
        fields.append(
            vm["name"]
        )

    with open(
        LOG_FILE,
        "w",
        newline="",
        encoding="utf-8"
    ) as f:

        writer = csv.DictWriter(
            f,
            fieldnames=fields
        )

        writer.writeheader()


def monitor(session, vms):

    with open(
        PID_FILE,
        "w"
    ) as f:

        f.write(
            str(os.getpid())
        )

    init_csv(vms)

    print()
    print(
        "开始后台监控"
    )
    print(
        "采样间隔:",
        INTERVAL,
        "秒"
    )
    print(
        "PID:",
        os.getpid()
    )
    print(
        "CSV:",
        LOG_FILE
    )
    print(
        "日志:",
        RUN_LOG
    )
    print()

    while True:

        try:

            timestamp = datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )

            host_cpu = get_host_cpu(
                session
            )

            if host_cpu is None:

                print(
                    timestamp,
                    "无法取得 Host CPU",
                    flush=True
                )

                time.sleep(
                    INTERVAL
                )

                continue

            vm_values = {}

            for vm in vms:

                vm_values[
                    vm["name"]
                ] = get_vm_cpu(
                    session,
                    vm
                )

            print(
                "----------------------------------------------",
                flush=True
            )

            print(
                "%s  Host CPU: %d MHz"
                % (
                    timestamp,
                    host_cpu
                ),
                flush=True
            )

            running = []

            for vm in vms:

                value = vm_values.get(
                    vm["name"]
                )

                if value is not None:

                    running.append(
                        (
                            vm["name"],
                            value
                        )
                    )

            running.sort(
                key=lambda x: x[1],
                reverse=True
            )

            running_names = set()

            for name, value in running:

                running_names.add(
                    name
                )

                print(
                    "  %-15s %6d MHz"
                    % (
                        name,
                        value
                    ),
                    flush=True
                )

            for vm in vms:

                if vm["name"] not in running_names:

                    print(
                        "  %-15s OFF"
                        % vm["name"],
                        flush=True
                    )

            row = {
                "timestamp": timestamp,
                "host_cpu_mhz": host_cpu
            }

            for vm in vms:

                value = vm_values.get(
                    vm["name"]
                )

                row[
                    vm["name"]
                ] = (
                    value
                    if value is not None
                    else ""
                )

            fields = [
                "timestamp",
                "host_cpu_mhz"
            ]

            for vm in vms:

                fields.append(
                    vm["name"]
                )

            with open(
                LOG_FILE,
                "a",
                newline="",
                encoding="utf-8"
            ) as f:

                writer = csv.DictWriter(
                    f,
                    fieldnames=fields
                )

                writer.writerow(row)

        except Exception as e:

            print(
                datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
                "监控异常:",
                repr(e),
                flush=True
            )

        time.sleep(
            INTERVAL
        )


def start():

    print()
    print(
        "=============================================="
    )
    print(
        "ESXi CPU 动态基线数据采集"
    )
    print(
        "=============================================="
    )
    print(
        "ESXi:",
        ESXI_HOST
    )
    print(
        "采样间隔:",
        INTERVAL,
        "秒"
    )
    print(
        "CSV:",
        LOG_FILE
    )
    print(
        "=============================================="
    )
    print()

    # 防止重复启动
    if os.path.exists(PID_FILE):

        try:

            with open(
                PID_FILE
            ) as f:

                old_pid = int(
                    f.read().strip()
                )

            os.kill(
                old_pid,
                0
            )

            print(
                "监控已经在运行"
            )

            print(
                "PID:",
                old_pid
            )

            return

        except:
            pass

    session = login()

    print()
    print(
        "正在发现 VM..."
    )

    vms = discover_vms(
        session
    )

    if not vms:
        raise RuntimeError(
            "没有发现 VM"
        )

    print()
    print(
        "发现 VM："
    )

    for vm in vms:

        print(
            "  %-15s ID=%s"
            % (
                vm["name"],
                vm["id"]
            )
        )

    # ======================================================
    # 登录和 VM 发现全部完成以后，才进行 daemon 化
    # ======================================================

    pid = os.fork()

    if pid > 0:

        print()
        print(
            "登录及 VM 发现成功"
        )
        print(
            "监控已转入后台"
        )
        print(
            "后台 PID:",
            pid
        )
        print()
        print(
            "现在可以关闭 SSH / FRP"
        )

        return

    # 子进程脱离终端
    os.setsid()

    # 第二次 fork，避免重新获得控制终端
    pid = os.fork()

    if pid > 0:
        os._exit(0)

    # stdin / stdout / stderr 全部重定向
    devnull = open(
        os.devnull,
        "r"
    )

    log = open(
        RUN_LOG,
        "a",
        buffering=1
    )

    os.dup2(
        devnull.fileno(),
        sys.stdin.fileno()
    )

    os.dup2(
        log.fileno(),
        sys.stdout.fileno()
    )

    os.dup2(
        log.fileno(),
        sys.stderr.fileno()
    )

    devnull.close()

    monitor(
        session,
        vms
    )


if __name__ == "__main__":

    try:

        start()

    except KeyboardInterrupt:

        print(
            "已取消"
        )

    except Exception as e:

        print(
            "启动失败:",
            repr(e)
        )

        sys.exit(1)

PY

chmod +x /tmp/esxi_cpu_monitor.py
python3 /tmp/esxi_cpu_monitor.py
