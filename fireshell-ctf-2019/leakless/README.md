# leakless
https://github.com/alissonbezerra/fireshell-ctf-2019/tree/master/pwn/leakless  
## 概要  
readで標準入力からの入力を受け取る。  
## 解法  
シンプルにBOFで解ける。  
と思っていたのだが、実際に問題に手を付けてみると、x86の関数呼び出しのやり方を忘れていたので時間がかかった。  
ROPでGOTからlibcのアドレスをリークしてlibc databaseからlibcを特定する。  
後はもう一度BOFできる関数を呼び出して、ret2libcでsystem関数を実行する。  

write-upを調べていたら、libc databaseを使わずに解く方法もあるらしいので、後でこっちでも解いてみる。  
## 解法 2(ret2dl-resolve)  
今回の問題ではlibcの配布がされていない為、リークされたlibcのアドレスを元にlibcのバージョンを特定する必要があった。  
(解き終わってから気づいたので、上の解法では触れていない...)  
このような場合、libc databseを用いてリンクしているlibcのバージョンを特定し、シンボルのオフセットを計算する必要がある。  
しかしret2dl-resolveの手法を用いた場合、libcの種類を問わずにlibc内の任意の関数を実行する事ができる。  
### _dl_runtime_resolveと_dl_fixup  
(後日ブログにまとめる)  

参考: https://ypl.coffee/dl-resolve/  
