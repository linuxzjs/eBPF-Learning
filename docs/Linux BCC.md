# `Linux BCC`

# 一、`Background`



# 二、`compile`

```shell
git clone https://github.com/iovisor/bcc.git
mkdir bcc/build; cd bcc/build
cmake ..
make       #sudo apt-get install libpolly-16-dev
sudo make install
cmake -DPYTHON_CMD=python3 .. # build python3 binding
pushd src/python/
make
sudo make install
popd
```

编译完成后进行功能验证：
```shell
cd /usr/share/bcc/tools

jinsheng@jinsheng:/usr/share/bcc/tools$ sudo ./memleak -s 5
Attaching to kernel allocators, Ctrl+C to quit.
[04:25:49] Top 10 stacks with outstanding allocations:
	192 bytes in 1 allocations from stack
		0xffffffff88267387	kmem_cache_alloc_lru+0x267 [kernel]
		0xffffffff88267387	kmem_cache_alloc_lru+0x267 [kernel]
		0xffffffff88310f24	__d_alloc+0x34 [kernel]
		0xffffffff883142f6	d_alloc_pseudo+0x16 [kernel]
		0xffffffff882ef89e	alloc_file_pseudo+0x6e [kernel]
		0xffffffff8836173e	__anon_inode_getfile+0x8e [kernel]
		0xffffffff88361864	anon_inode_getfile+0x14 [kernel]
		0xffffffff881a61b7	__do_sys_perf_event_open+0x8a7 [kernel]
		0xffffffff881a6682	__x64_sys_perf_event_open+0x22 [kernel]
		0xffffffff87e06ce6	x64_sys_call+0x1426 [kernel]
		0xffffffff89017531	do_syscall_64+0x81 [kernel]
		0xffffffff89200130	entry_SYSCALL_64_after_hwframe+0x78 [kernel]
```
通过验证说明`BCC`已编译成功可以正常使用。
# 三、`DEMO`



# 四、`Reference`

[IO Visor Project](https://github.com/iovisor)

[iovisor/bcc: BCC - Tools for BPF-based Linux IO analysis, networking, monitoring, and more](https://github.com/iovisor/bcc)