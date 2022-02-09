# elementary stack
https://bitbucket.org/ptr-yudai/writeups-2020/src/master/SECCON_Beginners_CTF_2020/elementary_stack/  
## 概要  
配列の範囲外書き込みが行えるので、そこからGOT Overwriteを使ってprintfを書き込むことでFSBできるようにして、libcのアドレスをリーク。  
そこから算出したlibc上のsystemのアドレスをもう一度GOT Overwriteするとシェルが動く。  
## 解法　　
配列のindexを指定して値を書き込める。  
ただしwhileの無限ループを使っており、main関数にret命令が存在しないので、リターンアドレスの書き換えは行えない。  
義務教育で習ったようにC言語は配列の領域外書き込みを行いやすく、この問題でも同様に領域外に対する書き込みのチェックが行われていないので、範囲外の値や負の数を入力して領域外に書き込める。  
これがとっかかりの脆弱性となっている。  
gdbを使って書き込みの処理を追ってみると、以下のような処理がある。  
`mov QWORD PTR [rbp+rax*8-0x40], rdx
`  
これはindex指定後の入力した値を書き込む処理であり、このときの`rax`レジスタにはindexの値が入っており、`rdx`レジスタには入力した値が入っている。  
つまり、  
`mov QWORD PTR [rbp+index*8-0x40], buffer`  
となる。  
またこの時のスタックを見てみると、`rbp-0x50`にbufferを書き込むアドレスが入ってる事がわかる。  
先程述べたように`rbp+index*8-0x40`に対して書き込みが行われるので、indexの値を-2にする事で、ここに対して書き込みが行える。  
つまり任意のアドレスに対して書き込みが行えて、かつ`Partial RELRO`である事から、GOT Overwriteができる。  
シェルを奪う事を考えるとlibcのアドレスが必要になるので、GOT Overwriteからlibcのアドレスリークに繋げたい。  
ここからどうやってリークすればいいのかわからず、他の方のwrite-upを拝見したところ、GOTを`printf`にする事によってFSBを起こせるようにして、スタック上にある`__libc_start_main`のアドレスをリークさせていた。  
例えば今回の場合は`atol`のGOTを書き換えるのだが、ソースコードを見てみると`atol`は以下のような使われ方をしている。  
```c
return atol(buf);  
```
ここで重要なのは、ユーザーの入力がそのまま引数に渡されている事で、これを`printf`にGOT Overwriteすると以下のようになる。  
```c
return printf(buf);
```
これはちゃんとした変換指定子を引数として渡していないprintf、つまりFSBが可能なprintfになってしまっている為、`%25$p`のような入力によってスタック上の任意のアドレスをリークできる。  
以上のことから、GOTを`printf`に書き換える事によってアドレスをリークできる事がわかったので、GOTの書き換えを行う。  
前述の`atol`関数のGOTを書き換えると都合が良さそうだが、直接書き換えを行った場合、`readlong`関数内の  
`read(0, buf, size)`  
の処理でFSBを実行するための入力(e.g. `%25$p`)が`atol`のGOTに書き込まれてしまい、エラーが怒ってしまう。  
つまり、  
bufを入力 -> `atol`のGOT書き換え -> FSB用のbufを入力 -> `atol`のGOTがFSB用のbufで上書きされる  
という流れになってしまい、アドレスのリークができない。  
なので、入力するバッファを`atol`のGOTよりも前に置くようにし、GOT上でオーバーフローを起こすことで`atol`の書き換えを行う。  
こうすることで、`atol`やその他動作に必要なGOTが上書きされるまでバッファを入力する事ができる。  
実際にGOTを見てみたのが以下。  
```
gef> got
GOT protection: Partial RelRO | GOT functions: 9
PLT:Not Found; GOT:0x600ff0 __libc_start_main@GLIBC_2.2.5
PLT:Not Found; GOT:0x600ff8 __gmon_start__
PLT:0x400580; GOT:0x601018 setbuf@GLIBC_2.2.5
PLT:0x400590; GOT:0x601020 printf@GLIBC_2.2.5
PLT:0x4005a0; GOT:0x601028 alarm@GLIBC_2.2.5
PLT:0x4005b0; GOT:0x601030 read@GLIBC_2.2.5
PLT:0x4005c0; GOT:0x601038 malloc@GLIBC_2.2.5
PLT:0x4005d0; GOT:0x601040 atol@GLIBC_2.2.5
PLT:0x4005e0; GOT:0x601048 exit@GLIBC_2.2.5
```  
`atol`の前には、`malloc`や`read`のGOTがある事がわかる。  
`read`は前述の通り`readlong`関数で使われているので、書き換えはできない。  
よって残る選択肢は`malloc`のみになるが、`malloc`はmain関数の最初の方でのみ呼ばれているので、ここをバッファの書き込み先として指定する。  
つまり、一度流れを整理すると  
1. indexに-2を入力する事で、bufferの入力先アドレスを書き換え  
2. `malloc@got`のアドレスを入力する事で、GOT Overwriteできるようにする
3. indexの入力で8byteのパディング+`printf@plt`のアドレスを入力する事で、`malloc`と`atol`をGOT Overwrite  
(これ以降、`malloc`のGOTはbufferの受け皿の役割を果たすことになる。)  
4. `printf`でFSBできるので、libcのアドレスをリーク  

といった流れになる。  
ただしこの操作以降で、8byte以上のバッファを入力してしまうと`atol`のGOTを再書き換えしてしまうので注意。  
長くなってしまったが、これでようやくlibcのアドレスを得ることができるようになった。  
`readlong`関数の`atol`関数を呼ぶ時(書き換え後は実質`printf`だが)のスタックの状態から、`%25$p`の入力で、`__libc_start_main + 213`のアドレスをリークできる事がわかったので、リーク。  
あとは`system@libc`のアドレスを算出し、前述したように8byte以上の入力で`atol`のGOTを書き換えれるので、`system@libc`に書き換える。  
この時、パディングとしての8byteに`/bin/sh\0`を使うと、そのまま引数として渡せてシェルを奪えるので一石二鳥。  