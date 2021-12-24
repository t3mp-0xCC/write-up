# greeting  
```https://github.com/ByteBandits/writeups/raw/master/mma-ctf-2016/pwn/greeting```
## 概要  
名前を入力すると、問題名通り挨拶をしてくれる。  
checksecの結果にNo RELROが含まれているので、GOT Overwriteするのではないかと推測。  
## 解法  
名前を出力する時のprintfにFSBが存在するので、これを使ってGOT Overwriteをする。  
FSBをやるのが久しぶりなので復習すると、FSBが存在する時に、  
```AAAA%6$hhn```のような文字列をprintfで表示させると、0x41414141に対して%6$xで表示されるスタック内のアドレスが書き込まれる。  
これを利用する事でGOT Overwriteを実現する。  
しかし、今回の場合、FSBの後にいい感じに引数を設定できる関数が存在しないので、このままではGOT Overwriteしてもsystem('/bin/sh')を実行するに至らない。  
そこで.fini_arrayを書き換えることでもう一度main関数を呼び出す事を考える。  
.fini_arrayは関数のアドレスが格納された配列であり、main関数終了後に呼び出される関数が格納されている。  
なので、ここをmain関数のアドレスに書き換える事でもう一度main関数内の処理を実行させ、引数を設定できそうなstelenをGOT Overwriteした上で、/bin/shをstrlenに引数として渡すことで、system('/bin/sh')を実行する。  