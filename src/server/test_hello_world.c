int hello_world(struct pt_regs *ctx) {
        bpf_trace_printk("Hello world from eBPF!\n");
        return 0;
}
