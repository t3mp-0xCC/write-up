# instant_httpserver
https://github.com/ypl-coffee/ContrailCTF-2019/tree/master/instant_httpserver  
## 概要
問題名通りの簡素なHTTPを喋るサーバー。  
## 解法  
GETメソッドの後にバッファを書くことでBOFできる。  
しかしSSPが有効なのでcanaryをリークする必要がある。  
canaryを破壊した場合とそうでない場合でレスポンスが異なるので、これを利用して総当りでcanaryを特定する。  
canaryを特定した事でRIPを奪えるようになるが、ROPしようにもPIEが有効なのでこれをバイパスする必要がある。  
そこで実行ファイルのベースアドレスをリークする。  
