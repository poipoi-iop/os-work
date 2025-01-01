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
代码位于`redis-ebpf-analysis`文件夹下

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

### redis-ebpf-analysis——Redis 监控系统设计文档

#### 1. 项目概述
本项目旨在实现一个Redis监控系统，能够捕获和分析Redis相关的系统调用，识别Redis协议的请求和响应，并提供相应的监控信息，如请求方法、延迟等。项目主要包含Go语言编写的用户态程序和eBPF程序，两者通过共享映射进行通信。

#### 2. 功能需求
##### 2.1. 系统调用捕获
- 拦截并处理与Redis相关的 `write` 和 `read` 系统调用。
- 在系统调用进入和退出时进行相应的处理，记录必要的信息。

##### 2.2. Redis协议解析
- 识别Redis协议中的不同数据类型，如简单字符串、错误、整数、批量字符串和数组。
- 解析Redis命令、推送事件、PING请求等，并提取相关信息。

##### 2.3. 监控信息输出
- 输出Redis请求的方法（如COMMAND、PUSHED_EVENT、PING）。
- 计算并输出请求的延迟时间（从写入到读取完成的时间间隔）。
- 以可读的格式打印Redis协议中的数据内容。

**输出内容如下：**
<img src="./assets/test1.png" height="75%" width="75%">
<img src="./assets/test2.png" height="75%" width="75%">

#### 3. 模块设计
##### 3.1. 用户态程序（Go语言）
###### 3.1.1. 资源管理模块
- 负责允许当前进程锁定eBPF资源的内存，确保程序能够正常加载和运行eBPF程序。
- 加载预编译的eBPF程序和映射到内核中，建立用户态和内核态之间的通信基础。

###### 3.1.2. 系统调用跟踪模块
- 使用 `link.Tracepoint` 函数，在 `syscalls/sys_enter_write`、`syscalls/sys_exit_write`、`syscalls/sys_enter_read` 和 `syscalls/sys_exit_read` 等系统调用点进行跟踪。
- 为每个跟踪点注册相应的处理函数，如 `pgObjs.HandleWrite`、`pgObjs.HandleWriteExit`、`pgObjs.HandleRead` 和 `pgObjs.HandleReadExit`。

###### 3.1.3. 事件处理模块
- 从内核通过 `perf` 事件获取L7事件信息，使用 `perf.NewReader` 函数创建事件读取器，从 `pgObjs.L7Events` 映射中读取数据。
- 解析读取到的事件数据，判断协议类型是否为Redis。如果是，则进一步解析Redis协议内容，提取请求方法、参数等信息。
- 计算并输出请求的延迟时间，以及将Redis协议中的数据转换为可读字符串并打印输出。

##### 3.2. eBPF程序（C语言）
###### 3.2.1. 数据结构定义
- 定义了一系列用于存储系统调用参数、请求和事件信息的数据结构，如 `write_args`、`read_args`、`socket_key`、`l7_request` 和 `l7_event` 等。
- 这些结构用于在内核态记录系统调用的相关信息，以及在用户态和内核态之间传递数据。

###### 3.2.2. 系统调用处理函数
- `process_enter_of_syscalls_write`：处理 `write` 系统调用进入时的操作。从映射中获取或初始化 `l7_request` 结构，检查并设置Redis协议相关信息（如协议类型、方法），复制有效载荷，更新活动请求映射。
- `process_exit_of_syscalls_write`：处理 `write` 系统调用退出时的操作。根据返回值判断写入是否成功，若成功则填充 `l7_event` 结构并通过 `bpf_perf_event_output` 将事件发送到用户空间。
- `process_enter_of_syscalls_read`：处理 `read` 系统调用进入时的操作。记录读取参数到 `active_reads` 映射中。
- `process_exit_of_syscalls_read`：处理 `read` 系统调用退出时的操作。从映射中获取相关信息，检查是否为Redis推送事件，若不是则从活动请求中获取信息，填充 `l7_event` 结构，根据读取结果设置状态，最后将事件发送到用户空间。

###### 3.2.3. 辅助函数
- `is_redis_ping`、`is_redis_pong`、`is_redis_command` 和 `is_redis_pushed_event`：用于识别Redis协议中的特定命令或事件。
- `parse_redis_response`：解析Redis响应的状态。

#### 4. 数据结构设计
##### 4.1. 用户态数据结构（Go语言）
###### 4.1.1. `L7Event` 结构体
- 用于在用户态表示L7层事件，包含了文件描述符（`Fd`）、进程ID（`Pid`）、状态（`Status`）、持续时间（`Duration`）、协议类型（`Protocol`）、是否加密（`Tls`）、方法（`Method`）、有效载荷（`Payload`）、有效载荷大小（`PayloadSize`）、有效载荷是否读取完整（`PayloadReadComplete`）、是否失败（`Failed`）、写入时间（`WriteTimeNs`）、线程ID（`Tid`）、序列号（`Seq`）和事件读取时间（`EventReadTime`）等字段。

###### 4.1.2. `bpfL7Event` 结构体
- 与内核态的事件结构相对应，用于从内核读取事件数据时进行转换。包含类似的字段，但类型和命名可能有所不同，以适配内核态和用户态之间的数据交互。

###### 4.1.3. `RedisValue` 接口
- 用于表示Redis协议中解析出的值，具体类型可以是字符串、整数或Redis值的数组。

##### 4.2. 内核态数据结构（C语言）
###### 4.2.1. `write_args` 结构体
- 存储 `write` 系统调用的参数，包括文件描述符（`fd`）、缓冲区指针（`buf`）、写入大小（`size`）和写入开始时间（`write_start_ns`）。
```c
struct write_args {
    __u64 fd;
    char* buf;
    __u64 size;
    __u64 write_start_ns;
};
```
###### 4.2.2. `read_args` 结构体
- 存储 `read` 系统调用的参数，包括文件描述符（`fd`）、缓冲区指针（`buf`）、读取大小（`size`）和读取开始时间（`read_start_ns`）。
```c
struct read_args {
    __u64 fd;
    char* buf;
    __u64 size;
    __u64 read_start_ns;  
};
```
###### 4.2.3. `socket_key` 结构体
- 用于作为映射的键，包含文件描述符（`fd`）、进程ID（`pid`）和是否加密（`is_tls`）字段。
```c
struct socket_key {
    __u64 fd;
    __u32 pid;
    __u8 is_tls;
};
```
###### 4.2.4. `l7_request` 结构体
- 表示L7层请求，包含写入时间（`write_time_ns`）、协议类型（`protocol`）、方法（`method`）、有效载荷（`payload`）、有效载荷大小（`payload_size`）、有效载荷是否读取完整（`payload_read_complete`）、请求类型（`request_type`）、序列号（`seq`）和线程ID（`tid`）等字段。
```c
struct l7_request {
    __u64 write_time_ns;  
    __u8 protocol;
    __u8 method;
    unsigned char payload[MAX_PAYLOAD_SIZE];
    __u32 payload_size;
    __u8 payload_read_complete;
    __u8 request_type;
    __u32 seq;
    __u32 tid;
};
```
###### 4.2.5. `l7_event` 结构体
- 表示L7层事件，包含文件描述符（`fd`）、写入时间（`write_time_ns`）、进程ID（`pid`）、状态（`status`）、持续时间（`duration`）、协议类型（`protocol`）、方法（`method`）、填充字段（`padding`）、有效载荷（`payload`）、有效载荷大小（`payload_size`）、有效载荷是否读取完整（`payload_read_complete`）、是否失败（`failed`）、是否加密（`is_tls`）、序列号（`seq`）和线程ID（`tid`）等字段。
```c
struct l7_event {
    __u64 fd;
    __u64 write_time_ns;
    __u32 pid;
    __u32 status;
    __u64 duration;
    __u8 protocol;
    __u8 method;
    __u16 padding;
    unsigned char payload[MAX_PAYLOAD_SIZE];
    __u32 payload_size;
    __u8 payload_read_complete;
    __u8 failed;
    __u8 is_tls;
    __u32 seq;
    __u32 tid;
};
```
#### 5. 关键算法与流程
##### 5.1. 系统调用跟踪流程
1. 用户态程序通过 `link.Tracepoint` 函数在指定的系统调用点进行跟踪注册。
2. 当系统调用发生时，内核态的相应处理函数被触发。
3. 处理函数根据系统调用的类型（进入或退出）和参数，执行相应的操作，如记录信息、更新映射或发送事件到用户空间。

##### 5.2. Redis协议解析流程
1. 在处理 `write` 或 `read` 系统调用时，根据有效载荷的前缀判断Redis协议的数据类型。
2. 对于不同的数据类型，使用相应的解析函数（如 `parseSimpleString`、`parseError`、`parseInteger`、`parseBulkString`、`parseArray`）进行解析。
3. 解析出的Redis值通过 `ConvertValueToString` 函数转换为可读字符串，以便输出或进一步处理。

##### 5.3. 事件处理流程
1. 用户态程序从 `perf` 事件读取器中获取内核发送的L7事件数据。
2. 根据事件的协议类型判断是否为Redis事件。
3. 如果是Redis事件，则解析事件中的有效载荷，获取请求方法和参数等信息。
4. 计算请求的延迟时间，并输出请求方法、延迟时间和有效载荷内容。

#### 6. 性能优化
##### 6.1. 内存分配优化
- 在eBPF程序中，由于堆栈空间有限，使用 `BPF_MAP_TYPE_PERCPU_ARRAY` 类型的映射来分配 `l7_request_heap` 和 `l7_event_heap`，避免在堆栈上分配大内存结构，减少栈溢出风险。

##### 6.2. 数据复制优化
- 在复制有效载荷时，使用 `bpf_probe_read` 函数直接从内核空间读取数据，避免不必要的数据拷贝操作，提高效率。

##### 6.3. 映射操作优化
- 在更新和查找映射元素时，合理使用 `BPF_ANY` 标志，减少不必要的映射操作开销。
- 限制映射的最大条目数，如 `active_reads`、`active_l7_requests` 和 `active_writes` 等映射，避免映射过度增长导致性能下降。

#### 7. 测试性能
- 由于使用eBPF检测redis事件，会在一定程度上降低redis的操作执行时间，因此通过perf文件夹中的measure.go测量开启eBPF程序对redis操作的影响。measure.go的主要作用是对 Redis 数据库的基本操作（SET、GET、UPDATE、DELETE）进行性能测试，测量每种操作在多次重复执行后的平均延迟时间。

**测试结果如下：**
<img src="./assets/comparison_data.png" height="75%" width="75%">

**对比图如下：**
<img src="./assets/latency_comparison.png" height="75%" width="75%">

**说明：**
- bpf2go是一个用于将 eBPF 程序（通常是用 C 语言编写）转换为 Go 语言代码的工具。在给定的代码中，通过//go:generate go run github.com/cilium/ebpf/cmd/bpf2go redis redis.c这行注释，指示go generate工具运行bpf2go来处理redis.c文件，并生成相应的 Go 代码。