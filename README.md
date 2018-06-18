# rpf
A new feature in the Linux kernel that resolves page faults over RDMA. This is used during post-copy container migration by copying memory pages from the source machine on demand. Latency during a page fault is critical, and this feature has been designed to minimize the latency.
