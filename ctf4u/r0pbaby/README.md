# r0pbaby  
```https://github.com/smokeleeteveryday/CTF_WRITEUPS/tree/master/2015/DEFCONCTF/babysfirst/r0pbaby```
## 概要  
libc baseと任意のlibc内のシンボルのアドレスが貰える状態でROPできる。  
かなり初心者向けの問題。  
だと思っていた...  
## 解法  
前述の通りlibc baseと任意のlibcシンボルのアドレスを貰えるので、ROPで```system('/bin/sh')```を実行する事を目指す。  
作成するROP chainは下の図のような感じ。  
```
+--------------+
| buffer * 0x8 |
+--------------+
| rop rdi; ret |
+--------------+
| /bin/sh addr |
+--------------+
| system@libc  |
+--------------+
```  
問題のバイナリは動的リンクしているので、lddコマンドでリンクしているlibcのパスを調べる。  
自分の環境では以下のような出力を得られた。  
```
$ ldd ./r0pbaby
        linux-vdso.so.1 (0x00007fff7f183000)
        libdl.so.2 => /usr/lib/libdl.so.2 (0x00007f3ecf45b000)
        libc.so.6 => /usr/lib/libc.so.6 (0x00007f3ecf28f000)
        /lib64/ld-linux-x86-64.so.2 => /usr/lib64/ld-linux-x86-64.so.2 (0x00007f3ecf68d000)
```  
libcのパスは/usr/lib/libdl.so.2のようなので、ここからROP Gadgetと```/bin/sh```のアドレスを探す。  
```
$ rp --file=/usr/lib/libc.so.6 --unique --rop=2 | grep "pop rdi ; ret"
0x00027f75: pop rdi ; ret  ;  (460 found)
```  
```/bin/sh```のアドレスはvimのxxdでlibc内を調べて取得した。  
(もっといい方法があるような気もする。)  
必要なアドレスは全部得られたので、あとはlibc baseに各アドレスを足して実際のアドレスを出すだけ...  
かと思われたのだが、実行してみるとうまく動いてくれない。  
gdbで見てみると、どうも狙ったアドレスにretできていないようだった。  
ここでかなり苦戦したが、gdbから得られるlibc baseのアドレスと、プログラムの出力から得られるlibc baseのアドレスが異なる事に気づいた。  
調べてみると、libc baseの取得にdlopenという関数を使っており、これはELFのヘッダ情報からアドレスを取得しているようなのだが、checksecを見てみると、このバイナリはPIEが有効になっている。  
```
$ checksec --file=./r0pbaby
[*] '/home/t3mp/CTF/ctf4u/r0pbaby/r0pbaby'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
    FORTIFY:  Enabled
```  
PIEはメモリ上に展開されたバイナリのアドレスをランダマイズする機能なので、これによってバイナリ内に存在するアドレスの情報と、実際のアドレスの情報に差異が生じたのだと思う。  
以上の理由からプログラムから得られるlibc baseはアテにならない事がわかったので、libc内のシンボルのアドレスからlibcのオフセットを引いてlibc baseを取得する事にした。  
すると狙ったとおりにROPが動いてシェルが起動した。  