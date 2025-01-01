import paramiko
import os
from time import sleep

# 服务端信息
SERVICE_IP = "server"  # 服务端 IP 地址
SERVICE_USER = "root"  # 服务端 SSH 用户
SERVICE_PASS = "Liu20021231"  # 服务端 SSH 密码
DURATION = 10  # 信息采集持续时间，单位为秒


def test():
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname=SERVICE_IP, port=22, username=SERVICE_USER, password=SERVICE_PASS)

        # 获取进程 PID
        stdin, stdout, stderr = client.exec_command("pgrep -f workload.py")
        pid = stdout.read().decode('utf-8')

        # 调用终端
        shell = client.invoke_shell()

        # 查看堆栈追踪
        command = f"cd /{SERVICE_USER}/os-work && perf record -e sched:sched_switch -p {pid} -a sleep {DURATION}"
        print(f"Running command on server: {command}")
        # 运行命令
        shell.send(command + '\n')
        # 等待 perf 采集数据，并留出一秒作为冗余
        sleep(DURATION + 1)

        sftp = client.open_sftp()

        sftp.get(f"/{SERVICE_USER}/os-work/perf.data", "perf.data")
        os.system("perf script")

        shell.close()
        client.close()
    except Exception as e:
        print(f"Error collecting data: {e}")


if __name__ == "__main__":
    test()