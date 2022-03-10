# aria-writer
https://github.com/hsncsclub/HSCTF-6-Problems/tree/master/pwn/aria-writer
## 概要
file:
```
aria-writer: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /home/t3mp/ctf/HSCTF-6-Problems/pwn/aria-writer/bin/ld-2.27.so, for GNU/Linux 3.2.0, BuildID[sha1]=ec995234b09963a3579e7cfcabc612be3a5a24f6, not stripped
```
checksec:
```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x3fd000)
```
サイズを指定したmallocおよび直前にmallocされたチャンクのfreeができる。  
glibc 2.27でdouble freeができるが、この手の問題よくあったshowコマンドのようなメモリ上の値をリークできる機能が存在しないため、リークの方法について考える必要があった。  
## 解法
Partial RELROでGOT Overwriteができるため、何かしらの関数を`puts@plt`に書き換え、これを足がかりにlibcのアドレスをリークする事を考える。  
main関数を眺めてみると、引数的に`free(global)`が使いやすそうに見える。  
(globalは直前にmallocしたチャンクのアドレスを保管する変数)  
しかし、global変数に任意の関数のGOTを書き込み、`free@got`を`puts@plt`に書き換えてしまうと、freeが使えず、double freeによる書き換えが行えなくなり、シェルを起動する事ができなくなってしまうので、リークする前にGOT OverwriteでOne-Gadgetを起動する準備もする必要がある。  
よって、全体的な流れとしては以下のようになる。  
1. global、`free@got`、`exit@got`をそれぞれdouble freeを使って書き換える直前の状態にする。  
(既に数回double freeの問題を解いているので詳しくは解説しないが、それぞれあと1回のmallocで書き換えれるようにする。)  
2. `free@got`を`puts@plt`に書き換え(出力用)
3. globalを`setvbuf@got`に書き換え(libcアドレス用)
4. freeを実行。書き換えによって`puts(global)`が実行される
5. 取得したlibcのアドレスを元にOne-Gadgetのアドレスを算出し、`exit@got`を書き換える
6. 無効な選択をする事でexitが呼び出され、シェルが起動する

書き損ねてしまったが、プログラムの最初には名前の入力を求められる。  
が、特に使いみちを思いつかなかったので使わなかった。何に使うことを想定していたのだろうか...