import paramiko
import os
from time import sleep

# 服务端信息
SERVICE_IP = "server"  # 服务端 IP 地址
SERVICE_USER = "root"         # 服务端 SSH 用户
SERVICE_PASS = "Liu20021231" # 服务端 SSH 密码
DURATION = 30           # 信息采集持续时间，单位为秒

def test():
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname=SERVICE_IP, port=22, username=SERVICE_USER, password=SERVICE_PASS)

        # 启动 perf 记录 Redis 进程的性能数据
        # 需要先确认 Redis 进程的 PID
        stdin, stdout, stderr = client.exec_command("pgrep redis-server")

        # 获得 redis-server 的 pid
        redis_pid = stdout.read().decode('utf-8')
        if redis_pid is None or redis_pid == "":
            # 如果没有 Redis 进程 PID，返回
            print("No Redis process found, exiting...")
            return

        shell = client.invoke_shell()

        # 使用 perf 工具记录 Redis 进程的性能数据，监控调用栈
        command = f"perf record -p {redis_pid.strip()} -F 200 -g sleep {DURATION}"
        print(f"Running command on server: {command}")

        shell.send(command + '\n')

        sleep(DURATION + 1)

        sftp = client.open_sftp()

        sftp.get("perf.data", "perf.data")
        sftp.close()
        shell.close()
        client.close()
        os.system("perf script > perf.out")

        os.system("/root/FlameGraph/stackcollapse-perf.pl perf.out > perf.folded")
        os.system("/root/FlameGraph/flamegraph.pl perf.folded > flamegraph.svg")

    except Exception as e:
        print(f"Error processing: {e}")

if __name__ == "__main__":
    test()