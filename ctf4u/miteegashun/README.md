# miteegashun  
```http://shell-storm.org/repo/CTF/CSAW-2013/Exploitation/miteegashun-400/```
## 概要  
ユーザーの入力を受け取る関数のRAをdataセクションに移動させている上に、dataセクション上をスタックとして扱う動作をする。  
(stack pivot状態...?)  
こんなに複雑な事をしているのにstatically linkedかつstrippedなので動作を把握するのが大変だった。  
## 解法  
舞台がスタックからdataセクションに移っただけなので、オーバーフローでRAを書き換えてEIPを奪う。  
しかし、実行可能な領域であるスタックに任意のコードを用意するにはスタックのアドレスのリークが必要になるが自分の技量ではできないので、dataセクション上のスタックでROPを実行し```execve("/bin//sh", ["/bin//sh"])```を実行する。  
x86でのシステムコールの仕様について知らなかったり、NULLの存在を忘れていたりしたので、ROP chainの作成に手間取ってしまった。  