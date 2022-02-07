# babyheap
https://github.com/alissonbezerra/fireshell-ctf-2019/tree/master/pwn/babyheap  
## 概要  
見慣れたheapを使ったメモアプリ。  
bssセクションを使って各操作のflagを管理する事で回数制限を設けている。  
UseAfterFreeの脆弱性を使ってうまい事flagの制限を回避しながらGOT Overwriteを目指す。  
## 解法
前述のUseAfterFreeの脆弱性を使ってbssセクションにある各機能管理用のflagをmallocして書き換える事を考えるが、当該の領域をmallocするには二回のmallocが必要になるのに対し、前述の回数制限のせいでmallocを一回しか実行できない。  
そこでバイナリを調べてみると、隠し機能として`fill`が存在する事がわかる。  
これはバイナリ内の機能で言うところの`create`と`edit`を同時に行うものであり、他の機能同様にflagによって管理されている。  
これによって二回目のmallocを実行すると同時に書き換えを行えるので、flagを全て書き換える。  
この時に`create`のflag部分をGOT上の`atoi`のアドレスにする事で、libcのアドレスをリークする。  
(flagが1の時のみ制限は機能するので、アドレスを書き込んでも問題なく`create`は動く。)  
また、各種flagの先にはポインタが存在し、これに対してmallocやfreeが行われるようになっている。  
つまりここを書き換えれば任意の領域をmallocして書き換える事ができる為、flagの書き換えついでにここもGOT上の`atoi`に書き換えることで用意にGOT Overwriteできる。  
あとはリークしたアドレスをもとにlibc上のsystem関数のアドレスを算出し、GOT Overwriteでシェルを起動するだけ。  
