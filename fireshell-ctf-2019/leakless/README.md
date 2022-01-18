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
今回の問題ではlibcの配布がされていない為、リークされたlibcのアドレスを元にlibcを特定する必要があった。  
(解き終わってから気づいたので、上の解法では触れていない...)  
このような場合、libc databseを用いてリンクしているlibcのバージョンを特定し、シンボルのオフセットを計算する必要がある。  
しかしret2dl-resolveの手法を用いた場合、libcの種類を問わずにlibc内の任意の関数を実行する事ができる。  
### _dl_runtime_resolve  
`_dl_runtime_resolve`を始めとした関数郡はプログラム内で任意のlibcの関数を初めて呼ぶ際に使われる。  
(ただし遅延バインドが有効な場合(Partial RELRO)に限る。)  
この関数郡は`.plt.got`セクションに関数の実態を持つlibcのアドレスを書き込むのに仕様され、書き込まれる前は一定の値が書き込まれている。  
![backtrace](https://github.com/t3mp-0xCC/write-up/raw/main/fireshell-ctf-2019/leakless/dl-resolve_backtrace.png) 

(実際にgdbで追ってみた時のバックトレース。)  
参考: https://ypl.coffee/dl-resolve/  
