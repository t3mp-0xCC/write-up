# SECCON Beginners 2021
## uma_catch
### 概要
馬を捕まえて踊らせるプログラム。  
BOFやFSB、UAFにdouble freeと脆弱性は複数存在するが、参加当時はBOF以外気づかなかったので解けなかった。  
### 解法
上記の通り複数の解法が存在する面白い問題だが、今回はFSBでアドレスリークしてUAFでtcache poisoningをしてOne-Gadgetを発火させる。  
詳細はexp.pyにコメントで書いているので省略。  
