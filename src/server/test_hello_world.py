from bpfcc import BPF

bpf_program = open("test_hello_world.c", "r").read()

b = BPF(text=bpf_program)
syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="hello_world")

print("eBPF program loaded.")
b.trace_print()