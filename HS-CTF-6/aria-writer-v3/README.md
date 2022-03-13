# aria-writer-v3
https://github.com/hsncsclub/HSCTF-6-Problems/tree/master/pwn/aria-writer-v3
## 概要
file:
```
aria-writer-v3: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /home/t3mp/ctf/HSCTF-6-Problems/pwn/aria-writer-v3/bin/ld-2.27.so, for GNU/Linux 3.2.0, BuildID[sha1]=8224829cd041248a25bd3d5e73b163f6be89bb3d, not stripped
```
checksec:
```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x3fe000)
```
[aria-writer](https://github.com/t3mp-0xCC/write-up/tree/main/HS-CTF-6/aria-writer)からの変更点は以下  
* Full RELROなのでGOT Overwriteは無理
* freeの回数制限を撤廃
* 名前を表示する選択肢が消えた => 選択画面で毎回名前が表示される
* 飛ぶだけで勝てるwin関数の追加 (使わない)

aria-writerではGOT Overwriteによってアドレスをリークしていたが、塞がれてしまったので別の方法を考える必要がある。  
## 解法
name付近をunsorted binにチャンクとして繋ぐことで`main_arena`のアドレスをリークする事を考え、tcacheに入らないサイズが`0x410`バイトよりも大きいチャンクを作ろうとしたが、`0x1a4`byteより大きいサイズを指定すると強制終了するようになっていたため、頭をかかえた。  
結局、unsorted binに繋がれるチャンクの作り方がわからず、他の方のwrite-upを少し覗いたところ、bss領域全体にチャンクを敷き詰めヒープ領域一部であるかのように扱う事でname付近をunsorted binに繋いでいた。  
まず、最初に入力できるnameをunsorted binに繋ぐチャンクのヘッダとして扱うため、名前を`0x501`にする。  
(サイズは`0x500`だが、チャンクのヘッダはサイズ以外にも各種フラグをbitで管理しているため、`0x501`のようになる)  
一見、これだけでunsorted binに繋ぐためのチャンクは完成したように思えるが、メモリ上の下とさらにその下のチャンクの`PREV_INUSE`が立っていないとtopに結合されてしまうため、条件に合った偽チャンクをあと2つ作る。  
(前述したようにfreeの回数制限は存在しないため、double freeによって何回も任意のアドレスを書き換える事ができる。)  
あとはnameをヘッダとするチャンクを解放する事でunsorted binに繋がれる。  
しかしこのままだとヘッダのサイズ以降のNULLが邪魔をして`fd`および`bk`にある`main_arena`のアドレスをリークできないため、ヘッダ付近を適当な文字で埋める事でoverreadさせ、アドレスを表示できるようにする。  
あとは適当なチャンクに`/bin/sh`を書き込み、`__free_hook`にsystem関数のアドレスを書き込んでチャンクを解放する事でシェルが起動する。