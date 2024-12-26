//go:build ignore

#include "redis.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// 由于 BPF 堆栈限制为 512 字节，因此我们不在 bpf 堆栈上分配，而是在每个 CPU 数组映射上分配
struct {
     __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
     __type(key, __u32);
     __type(value, struct l7_request);
     __uint(max_entries, 1);
} l7_request_heap SEC(".maps");

// 由于 BPF 堆栈限制为 512 字节，因此我们不在 bpf 堆栈上分配，而是在每个 CPU 数组映射上分配
struct {
     __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
     __type(key, __u32);
     __type(value, struct l7_event);
     __uint(max_entries, 1);
} l7_event_heap SEC(".maps");

// 将读取的参数从进入传输到退出
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64); // pid_tgid
    __uint(value_size, sizeof(struct read_args));
    __uint(max_entries, 10240);
} active_reads SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 32768);
    __type(key, struct socket_key);
    __type(value, struct l7_request);
} active_l7_requests SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64); // pid_tgid
    __uint(value_size, sizeof(struct write_args));
    __uint(max_entries, 10240);
} active_writes SEC(".maps");

// M与用户空间应用程序共享 l7 事件的映射
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} l7_events SEC(".maps");

// 处理客户端触发的 write 系统调用的输入
static __always_inline
int process_enter_of_syscalls_write(void* ctx, __u64 fd, char* buf, __u64 payload_size) {
    __u64 timestamp = bpf_ktime_get_ns();
    __u64 id = bpf_get_current_pid_tgid();

    // 从 eBPF 映射中检索 l7_request 结构
    int zero = 0;
    struct l7_request *req = bpf_map_lookup_elem(&l7_request_heap, &zero);
    if (!req) {
        return 0;
    }

    // 检查 L7 协议是否为 RESP，否则设置为未知
    req->protocol = PROTOCOL_UNKNOWN;
    req->method = METHOD_UNKNOWN;
    req->write_time_ns = timestamp;
    if (buf) {
        if (is_redis_ping(buf, payload_size)) {
            req->protocol = PROTOCOL_REDIS;
            req->method = METHOD_REDIS_PING;

	    struct write_args args = {};
            args.fd = fd;
            args.write_start_ns = timestamp;
            bpf_map_update_elem(&active_writes, &id, &args, BPF_ANY);
        } else if (!is_redis_pong(buf, payload_size) && is_redis_command(buf, payload_size)) {
            req->protocol = PROTOCOL_REDIS;
            req->method = METHOD_REDIS_COMMAND;

	    struct write_args args = {};
            args.fd = fd;
            args.write_start_ns = timestamp;
            bpf_map_update_elem(&active_writes, &id, &args, BPF_ANY);
        }
    }

    // 从数据包中复制有效载荷并检查其是否适合 MAX_PAYLOAD_SIZE
    bpf_probe_read(&req->payload, sizeof(req->payload), (const void *)buf);
    if (payload_size > MAX_PAYLOAD_SIZE) {
        // 我们无法复制所有内容（将 payload_read_complete 设置为 0）
        req->payload_size = MAX_PAYLOAD_SIZE;
        req->payload_read_complete = 0;
    } else {
        req->payload_size = payload_size;
        req->payload_read_complete = 1;
    }

    // 存储活动的 L7 请求结构以供稍后使用
    struct socket_key k = {};
    k.pid = id >> 32;
    k.fd = fd;
    long res = bpf_map_update_elem(&active_l7_requests, &k, req, BPF_ANY);
    if (res < 0) {
        bpf_printk("Failed to store struct to active_l7_requests eBPF map");
    }

    return 0;
}

static __always_inline
int process_exit_of_syscalls_write(void* ctx, __s64 ret) {
    __u64 timestamp = bpf_ktime_get_ns();
    __u64 id = bpf_get_current_pid_tgid();

    struct write_args *active_write = bpf_map_lookup_elem(&active_writes, &id);
    if (!active_write) {
        bpf_map_delete_elem(&active_writes, &id);
        return 0;
    }

    struct socket_key k = {};
    k.pid = id >> 32;
    k.fd = active_write->fd;

    struct l7_request *active_req = bpf_map_lookup_elem(&active_l7_requests, &k);
    if(!active_req) {
        return 0;
    }

    if (ret >= 0) {
    	// write success
        int zero = 0;
        struct l7_event *e = bpf_map_lookup_elem(&l7_event_heap, &zero);
        if (!e) {
            bpf_map_delete_elem(&active_writes, &id);
            bpf_map_delete_elem(&active_l7_requests, &k);
            return 0;
        }

        e->protocol = active_req->protocol;
        e->fd = k.fd;
        e->pid = k.pid;
        e->method = active_req->method;
        e->failed = 0; // success
        e->duration = timestamp - active_write->write_start_ns; // total write time

        // request payload
        e->payload_size = active_req->payload_size;
        e->payload_read_complete = active_req->payload_read_complete;
        e->is_tls = 0;

        // copy req payload
        bpf_probe_read(e->payload, MAX_PAYLOAD_SIZE, active_req->payload);

        bpf_map_delete_elem(&active_l7_requests, &k);
        bpf_map_delete_elem(&active_writes, &id);

        bpf_perf_event_output(ctx, &l7_events, BPF_F_CURRENT_CPU, e, sizeof(*e));
    } else {
        // write failed
        bpf_map_delete_elem(&active_writes, &id);
        bpf_map_delete_elem(&active_l7_requests, &k);
    }

    return 0;

}

// Processing enter of read syscall triggered on the server side
static __always_inline
int process_enter_of_syscalls_read(struct trace_event_raw_sys_enter_read *ctx) {
    __u64 id = bpf_get_current_pid_tgid();

    // 存储活动读取结构以供以后使用
    struct read_args args = {};
    args.fd = ctx->fd;
    args.buf = ctx->buf;
    args.size = ctx->count;
    long res = bpf_map_update_elem(&active_reads, &id, &args, BPF_ANY);
    if (res < 0) {
        bpf_printk("write to active_reads failed");     
    }

    return 0;
}

static __always_inline
int process_exit_of_syscalls_read(void* ctx, __s64 ret) {
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;

    // 从 read 系统调用的入口处检索活动读取结构
    struct read_args *read_info = bpf_map_lookup_elem(&active_reads, &id);
    if (!read_info) {
        return 0;
    }

    // 从写入系统调用中检索活动的 L7 请求结构
    struct socket_key k = {};
    k.pid = pid;
    k.fd = read_info->fd;

    // 从 eBPF 映射中检索活动的 L7 事件结构
    // 然后将此事件结构转发到用户空间应用程序
    int zero = 0;
    struct l7_event *e = bpf_map_lookup_elem(&l7_event_heap, &zero);
    if (!e) {
        bpf_map_delete_elem(&active_l7_requests, &k);
        bpf_map_delete_elem(&active_reads, &id);
        return 0;
    }

    struct l7_request *active_req = bpf_map_lookup_elem(&active_l7_requests, &k);
    if (!active_req) {
        // 检查 RESP 推送事件
        if (is_redis_pushed_event(read_info->buf, ret)) {
            // 重置先前的有效载荷值
            for (int i = 0; i < MAX_PAYLOAD_SIZE; i++) {
                e->payload[i] = 0;
            }
            e->protocol = PROTOCOL_REDIS;
            e->method = METHOD_REDIS_PUSHED_EVENT;
            
            // 从数据包中读取有效载荷并检查其是否适合 MAX_PAYLOAD_SIZE
            bpf_probe_read(e->payload, MAX_PAYLOAD_SIZE, read_info->buf);
            if (ret > MAX_PAYLOAD_SIZE) {
                e->payload_size = MAX_PAYLOAD_SIZE;
                e->payload_read_complete = 0;
             } else {
                e->payload_size = ret;
                e->payload_read_complete = 1;
            }
            
            bpf_map_delete_elem(&active_reads, &id);

            // 将事件转发给用户空间应用程序
            bpf_perf_event_output(ctx, &l7_events, BPF_F_CURRENT_CPU, e, sizeof(*e));
            return 0;
        }
        
        bpf_map_delete_elem(&active_reads, &id);
        return 0;
    }

    e->method = active_req->method;
    e->protocol = active_req->protocol;
    
    // 复制请求有效负载值
    e->payload_size = active_req->payload_size;
    e->payload_read_complete = active_req->payload_read_complete;
    bpf_probe_read(e->payload, MAX_PAYLOAD_SIZE, active_req->payload);

    if (read_info->buf) {
        if (e->protocol == PROTOCOL_REDIS) {
            if (e->method == METHOD_REDIS_PING) {
                e->status =  is_redis_pong(read_info->buf, ret);
            } else {
                e->status = parse_redis_response(read_info->buf, ret);
                e->method = METHOD_REDIS_COMMAND;
            }
        }
    } else {
        bpf_map_delete_elem(&active_reads, &id);
        return 0;
    }

    bpf_map_delete_elem(&active_reads, &id);
    bpf_map_delete_elem(&active_l7_requests, &k);

    
    long r = bpf_perf_event_output(ctx, &l7_events, BPF_F_CURRENT_CPU, e, sizeof(*e));
    if (r < 0) {
        bpf_printk("Failed write to l7_events to userspace");       
    }

    return 0;
}


// /sys/kernel/debug/tracing/events/syscalls/sys_enter_write/format
SEC("tracepoint/syscalls/sys_enter_write")
int handle_write(struct trace_event_raw_sys_enter_write* ctx) {
    return process_enter_of_syscalls_write(ctx, ctx->fd, ctx->buf, ctx->count);
}

SEC("tracepoint/syscalls/sys_exit_write")
int handle_write_exit(struct trace_event_raw_sys_exit_write* ctx) {
    return process_exit_of_syscalls_write(ctx, ctx->ret);
}

// /sys/kernel/debug/tracing/events/syscalls/sys_enter_read/format
SEC("tracepoint/syscalls/sys_enter_read")
int handle_read(struct trace_event_raw_sys_enter_read* ctx) {
    return process_enter_of_syscalls_read(ctx);
}

// /sys/kernel/debug/tracing/events/syscalls/sys_exit_read/format
SEC("tracepoint/syscalls/sys_exit_read")
int handle_read_exit(struct trace_event_raw_sys_exit_read* ctx) {
    return process_exit_of_syscalls_read(ctx, ctx->ret);
}
