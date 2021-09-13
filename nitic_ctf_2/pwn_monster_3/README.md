# pwn monster 3
## 概要
バトルに勝利してもflagを得ることができないようになったらしい。  
## 解法
バッファの先にmy_monster_cryの関数ポインタが存在するので、これをflagを表示するshow_flag関数のアドレスに書き換える。  