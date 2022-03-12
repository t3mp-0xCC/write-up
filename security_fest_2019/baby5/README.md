# Baby 5
https://bitbucket.org/ptr-yudai/writeups/src/master/2019/Security_Fest_2019/Baby5/
## 概要
file:
```
baby5: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /home/t3mp/ctf/Security_Fest_2019/Baby5/ld-2.27.so, for GNU/Linux 3.2.0, BuildID[sha1]=fd2ab32a642c79dbd296243c8e1fc43f021b158f, stripped
```
checksec:
```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x3fe000)
```

ありがちなheapを使ったメモ形式の問題。  
GOT OverwriteもできるしNo PIEでシンボルのアドレスの特定も楽でありながら、showコマンドを使用したUAFもできるので、なんとでもできそうである。  
## 解法
解く方法についてはあまり悩む事はなく、unsorted binにチャンクを置くように調整して、前述のUAFを使って`main_arena`のアドレスをリーク、そこからlibc baseのアドレスを算出した。  
あとはdouble freeを使って`__free_hook`にOne-Gadgetのアドレスを書き込んでシェルを起動した。  
(チャンクに`/bin/sh`を書き込んでsystem関数のアドレスを書き込んだ方がOne-Gadgetの条件を考えなくていいので、こっちのほうが良かったかも知れない)  
最初はGOT Overwriteでシェルを起動しようとしていたが、何故かプログラムが落ちるし、`__free_hook`を使ったほうが確実なので変更した。    
