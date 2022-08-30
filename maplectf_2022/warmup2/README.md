# warmup2
https://github.com/kam1tsur3/2021_CTF/blob/master/cakectf/pwn/got_it/chall  
## 概要  
fileコマンド  
```
./chal: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=81669793c7dbf9699b2ac8219a08893a58b86d56, for GNU/Linux 3.2.0, not stripped
```
checksec  
```
Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      PIE enabled
```
warmup1と異なる点は以下  
1. canaryが有効
2. win関数を削除
3. 入力の回数が2回に増加
3. 入力したバッファを出力する実装を追加

## 解法
warmup1と同様にバッファオーバーフローの脆弱性があるものの、PIEに加えてcanaryも有効かつwin関数が削除されたため、どうにかしてROPを組むことを考える。  
今回の場合はcanaryとwarmup1同様にPIEが有効であるため、この2つをどうにかする必要がある。  
canaryについては1回目の入力でcanaryの下位1byteまでBoFする事で文字列の一部として`printf`を介してリークできる。  
(canaryの下位1byteは常に0x00であるため別の文字で上書きしても問題ない)  
2回目の入力でcanaryを修復してwarmup1と同様にPartical overwriteを用いて`main`関数内で`vuln`関数を呼び出している箇所に飛ぶ事でもう一度BoFを行えるようにする。  
1回目と同様の手法でスタックにある`main + 0x44`をリークさせてtextセクションのアドレスを取得する。  
これによってROPを組むことができるので、`puts`の第一引数に`puts@got`のアドレスを渡す事で`puts@libc`のアドレスをリークする。  
ここからlibc内の任意の関数を使用してシェルを起動させたいところだが、今回の問題ではlibcが配布されていないので[libc databse](https://libc.rip/)を使用してリンクされているlibcを特定する。  
(ちなみに競技中はglibc 2.34から削除された`__libc_csu_init`が削除されていない事やUbuntuのLTSからglibc 2.31だと決め打ちしていました)  
libc databseはlibc内の関数の始まりの下位12bitを入力するだけでリンクされているlibcを特定するサービスで、今回は適当にリークさせた`puts`と`__libc_start_main`の下位12bitを入力したら`2.31-0ubuntu9.9`がリンクされている事を特定できた。  
後は`__libc_csu_init`に沢山あるgadgetをガチャガチャしてbssセクションにstack pivotしてread関数でOneGadgetが起動するROP Chainを作ってシェルを起動させた。  
(終わった後に気づいたが、stack pivotするよりはもう一回`vuln`関数を呼び出して普通に`system("/bin/sh")`するROP Chainを組んだほうが早かったかもしれない...)  
