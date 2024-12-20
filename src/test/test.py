import paramiko
import os
import subprocess
from time import sleep

# 服务端信息
SERVICE_IP = "192.168.0.215"  # 服务端 IP 地址
SERVICE_USER = "root"         # 服务端 SSH 用户
SERVICE_PASS = "Liu20021231" # 服务端 SSH 密码
PID = "25001"           # 进程 PID
DURATION = 10           # 信息采集持续时间，单位为秒

def test():
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname=SERVICE_IP, port=22, username=SERVICE_USER, password=SERVICE_PASS)

        shell = client.invoke_shell()

        # 查看堆栈追踪
        command = f"cd ~/os-work && perf record -e sched:sched_switch -p {PID} -a sleep {DURATION}"
        print(f"Running command on server: {command}")

        shell.send(command + '\n')

        sleep(DURATION + 1)

        sftp = client.open_sftp()

        sftp.get("perf.data", "perf.data")
        os.system("perf script")

        shell.close()
        client.close()
    except Exception as e:
        print(f"Error collecting data: {e}")


if __name__ == "__main__":
    test()
