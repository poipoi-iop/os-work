import matplotlib.pyplot as plt

# Latency values in microseconds
operations = ['SET', 'UPDATE', 'DELETE', 'GET']
latency_with_ebpf = [95.869, 95.926, 46.954, 93.577]
latency_without_ebpf = [50.767, 49.722, 24.538, 48.849]

x = range(len(operations))

# Create the plot
fig, ax = plt.subplots()

# Plotting the values
bar_width = 0.35
ax.bar(x, latency_with_ebpf, width=bar_width, label='With eBPF', align='center')
ax.bar([p + bar_width for p in x], latency_without_ebpf, width=bar_width, label='Without eBPF', align='center')

# Adding labels and title
ax.set_xlabel('Operation')
ax.set_ylabel('Latency (µs)')
ax.set_title('RESP Protocol Latency Comparison with and without eBPF')
ax.set_xticks([p + bar_width/2 for p in x])
ax.set_xticklabels(operations)
ax.legend(loc='upper center')

# Display the plot
plt.tight_layout()
plt.savefig('latency_comparison.png')  # Save the figure as a PNG file
plt.show()
