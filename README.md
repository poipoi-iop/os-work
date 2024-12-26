# 实验16：基于 eBPF 内核拓展的应用加速

## 环境

* **系统**：服务端和测试端均为 OpenEuler 24.03 LTS
* IP 地址：
  * 服务端
    * 公网：114.116.232.85
    * 私网：192.168.0.215

  * 测试端
    * 公网：123.249.14.30
    * 私网：192.168.0.117
* 平台：华为云
* 配置：两台 1 核 2G 云服务器

**更改 DNF 源：**

```shell
sed -i 's|http://repo.openeuler.org|https://mirrors.ustc.edu.cn/openeuler/|g' /etc/yum.repos.d/openEuler.repo
```

**添加 DNS 记录**

在 /etc/hosts 里添加记录方便使用别名：

```
192.168.0.215 server
192.168.0.117 test
```

**安装 eBPF 环境**（服务端和测试端）：

```shell
dnf update -y
dnf install clang llvm bcc kernel-headers -y
```

**服务端 hello world：**

test_hello_world.c：

```c
int hello_world(struct pt_regs *ctx) {
    bpf_trace_printk("Hello world from eBPF!\n");
    return 0;
}
```

test_hello_world.py：

```python
from bpfcc import BPF

bpf_program = open("test_hello_world.c", "r").read()
print(type(bpf_program))

b = BPF(text=bpf_program)
syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="hello_world")

print("eBPF program loaded.")
b.trace_print()
```

运行结果：

<img src="./assets/ebpf运行.png" height="75%" width="75%">

**测试端采集数据**：

简单的负载代码：

```python
from time import sleep

if __name__ == '__main__':
    while True:
        print("exec!")
        sleep(1)
```

test.py：

```python
import paramiko
import os
import subprocess
from time import sleep

# 服务端信息
SERVICE_IP = "server"  # 服务端 IP 地址
SERVICE_USER = "root"         # 服务端 SSH 用户
SERVICE_PASS = "Liu20021231" # 服务端 SSH 密码
PID = "25001"           # 进程 PID
DURATION = 10           # 信息采集持续时间，单位为秒

def test():
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname=SERVICE_IP, port=22, username=SERVICE_USER, password=SERVICE_PASS)

        # 调用终端
        shell = client.invoke_shell()

        # 查看堆栈追踪
        command = f"cd ~/os-work && perf record -e sched:sched_switch -p {PID} -a sleep {DURATION}"
        print(f"Running command on server: {command}")
		# 运行命令
        shell.send(command + '\n')
		# 等待 perf 采集数据，并留出一秒作为冗余
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

```

使用 paramiko 库在服务端运行 perf 命令生成 perf.data 后，将 perf.data 数据通过 SFTP 传回测试端，随后在测试端通过 perf script 展示数据。测试得到测试端可采集服务端负载数据。
运行结果：

<img src="./assets/采集数据.png" height="75%" width="75%">


## 基于eBPF的性能分析
### 使用bpftrace分析redis
跟踪所有系统调用
```
sudo bpftrace -e '
tracepoint:syscalls:sys_enter_* /comm == "redis-server"/ {
    @[probe] = count();
}' > redis_trace.out

```

跟踪所有函数调用
```
sudo -E stdbuf -oL bpftrace --unsafe -e '
uprobe:/usr/local/bin/redis-server:* {
    @[func] = count();
    
}

interval:s:10 {
    print(@);
    clear(@);
}

END {
    print(@);
}
' > redis_function_trace.out
```

列出可用的 uprobe 探针
`sudo bpftrace -l 'uprobe:/usr/local/bin/redis-server:*'`

### 使用perf工具分析
```sh
# 1. 执行 Redis 基准测试
redis-benchmark -h 192.168.0.215 -p 6379 -t set,get -n 1000000 -c 50 -d 64

# 2. 启动 perf 记录 Redis 进程的性能数据
# 需要先确认 Redis 进程的 PID
REDIS_PID=$(pgrep redis-server)

# 如果没有 Redis 进程 PID，退出脚本
if [ -z "$REDIS_PID" ]; then
    echo "No Redis process found, exiting..."
    exit 1
fi

# 使用 perf 工具记录 Redis 进程的性能数据，监控调用栈
sudo perf record -p $REDIS_PID -F 200 -g -- sleep 10

# 3. 生成 perf 的文本输出
sudo perf script > perf.out

# 4. 使用 Flamegraph 工具处理 perf 输出，生成火焰图
/root/FlameGraph/stackcollapse-perf.pl perf.out > perf.folded
/root/FlameGraph/flamegraph.pl perf.folded > flamegraph.svg

```
输出结果
![flamegraph](./assets/flamegraph.svg)

### 基于eBPF监测redis各个操作的延迟
代码位于`redis-ebpf`文件夹下

**构建运行**
```sh
go generate
go build
sudo ./redis
```

**使用以下方式检查 eBPF 程序日志**
```sh
sudo cat /sys/kernel/debug/tracing/trace_pipe
```
**程序输出**
```
2024/12/25 08:45:44 set name os-work, Latency: 3696 ns
2024/12/25 08:45:44 get name, Latency: 4849 ns
2024/12/25 08:45:44 del name, Latency: 5866 ns
2024/12/25 08:45:44 set name linzhicheng, Latency: 2940 ns
2024/12/25 08:45:44 set name os-work, Latency: 4374 ns
2024/12/25 08:45:44 get name, Latency: 6298 ns
2024/12/25 08:45:44 del name, Latency: 3752 ns
```