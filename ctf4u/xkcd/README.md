# xkcd
```https://github.com/smokeleeteveryday/CTF_WRITEUPS/tree/master/2016/DEFCONCTF/babysfirst/xkcd```
## 概要  
入力を受け付けるだけで初見だと何もわからないのでバイナリを読む必要がある。  
バイナリを読んでみると、strtokとstrcmpを使って特定の文字列に対してのみ応じるようになっている。
## 解法  
バイナリをGhidraに喰わせてgdbで動的解析してみると、```SERVER, ARE YOU STILL THERE? IF SO, REPLY "%s" (%d)```という形式でないと、```MALFORMED REQUEST```と表示して終了してしまう事がわかる。  
そして与えられた文字列をflagファイルの中身を格納しているアドレスの512バイト前にmemcpyを使ってコピーしている。  
そこから%d文字分だけ読み出して表示するようである。  
なので512文字を%sに入れた上で、%dを適当に増やせばレスポンスと一緒にflagが得られるように思える。  
しかしこの時の余分な数字がflagの文字数と合っていないと、```NICE TRY```と返され、終了してしまう。  
そこで総当りを実行して```NICE TRY```以外のレスポンスが得られた場合は別途表示するスクリプトを書いた。  