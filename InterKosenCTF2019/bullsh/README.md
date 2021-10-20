# bullsh
## 概要
lsとexit以外が通らないシェル。     
## 解法
一見何もできないように思えるが、lsとexit以外のコマンドを入力した時に出てくるエラー文にFSBの脆弱性が存在する。  
加えてPartical RELROなのでGOT Overwriteができる。  
One-Gadgetに飛ばしてもいいが、printfのgotをsystemに書き換え、そのまま引数として'/bin/sh'を渡す方針で行く。  
なんとなくカッコいいからだ。  

バイナリからgotとpltの情報を得て書き換える。  
しかしx64でのFSBはアドレスにNULLが入る関係で大変らしく、うまく通らなかったので、ライブラリに頼ることにした。  
https://github.com/hellman/libformatstr  
これで通ったが、仕組みが気になるのでpwntoolsのdebugで送受信を観察して後で追記する。  
