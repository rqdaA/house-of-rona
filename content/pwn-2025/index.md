+++
title = "2025年のpwn問を全部解くチャレンジ"
date = 2025-03-20
description = "打倒keymoon"
draft = true
[taxonomies]
tags = ["pwn"]
+++

[https://ptr-yudai.hatenablog.com/entry/2019/07/01/143652](https://ptr-yudai.hatenablog.com/entry/2019/07/01/143652)にインスパイアされました。
順次追加予定。

# 対象となる問題

- 問題のバイナリがある
- writeupが見つかる or 自分で解ける

---

# KalmarCTF (3/7 - 3/9)

## Merger

To be updated

## decore

To be updated

## loadall.js

To be updated

## KalmarVM

To be updated

## Maestro Revenge

To be updated

---

# tpctf (3/8 - 3/10)

[writeup](/tpctf-2025)

---

# utctf (3/14 - 3/16)

## Tic Tac Toe

Stack BoFでuserが勝ったかどうかのフラグを書き換えることができる \
[solver](./utctf_ticcatcoe.py)

## RETirement Plan

StackがRWXかつStack BoFがあるのでshellcode書くだけ \
[solver](./utctf_retirement.py)

## secbof

Stack BoFがあるのでROPでOpen Read Write (ORW)やるだけ\
[solver](./utctf_secbof.py)

## E-Corp Part 2

To be updated

---

# AlpacaHack round 10 (3/23)

## Oyster

0文字のパスワードを入力すると`cred.err`が0クリアされるので、`system("/bin/sh")`に到達できる。

[solver](./alpaca_r10_oyster.py)

## Kangaroo

`index = - (0x10000000000000000 /
72)`を入力するとOverflowが発生する。`-256204778801521543`を与えたところ`fn_clear`が書き換えられた。

`fn_clear`を`printf@plt`に向けることでFSBが可能になったので、これを用いてlibcをleakした。これで`system`関数のアドレスが得られたので、`fn_clear`を`system`関数に向けることでshellを得た。

[solver](./alpaca_r10_kangraroo.py)

## Takahashi

C++の`priority_queue`が使われている。構造体はvectorと変わらないようです。(vectorの構造とexploit方法は [C++のpwn/revで使うSTLコンテナの構造とバグパターン一覧](https://ptr-yudai.hatenablog.com/entry/2021/11/30/235732)を参照)

無限回、任意のタイミングでpushとpopができるということはすなわちheap上でのAAWを意味する。このプリミティブを用いて`tcache_per_thread`を書き換えることで`tcache poisoning`をして、priority_queueを破壊し、メンバをGOTに向けることでGOT Overwriteをした。

[solver](./alpaca_r10_takahashi.py)

## giraffe.ko
