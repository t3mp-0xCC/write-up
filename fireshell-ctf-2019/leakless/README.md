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