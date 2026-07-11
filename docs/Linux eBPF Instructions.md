# `Linux eBPF Instructions`

# 一、`Background`

[Linux eBPF](obsidian://open?vault=eBPF-Learning&file=docs%2FLinux%20eBPF) 介绍了`eBPF`基础理论及基本开发流程,本文将深入探讨`eBPF`指令集以加深对`eBPF`的理解,提高`eBPF`设计及开发能力实现预期目标。
# 二、`Instructions`

| `Class`    | `Value` | `Description`                     |
| ---------- | ------- | --------------------------------- |
| `BPF_LD`   | `0X00`  | `non-standard load operations`    |
| `BPF_LDX`  | `0X01`  | `load into register operations`   |
| `BPF_ST`   | `0X02`  | `store from immediate operations` |
| `BPF_STX`  | `0X03`  | `store from register operations`  |
| `BPF_ALU`  | `0X04`  | `32-bit arithmetic operations`    |
| `BPF_JMP`  | `0X05`  | `64-bit jump operations`          |
| `BPF_RET`  | `0X06`  | ``                                |
| `BPF_MISC` | `0X07`  | ``                                |



# 三、`Verifier`




# 四、`Reference`

[BPF and XDP Reference Guide — Cilium 1.17.6 documentation](https://docs.cilium.io/en/stable/reference-guides/bpf/index.html)

[BPF Documentation — The Linux Kernel documentation](https://www.kernel.org/doc/html/latest/bpf/index.html)

[1 BPF Instruction Set Architecture (ISA) — The Linux Kernel documentation](https://www.kernel.org/doc/html/latest/bpf/standardization/instruction-set.html)

