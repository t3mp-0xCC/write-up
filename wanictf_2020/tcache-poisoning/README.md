# tcache poisoning
## 概要
heap問では定番のメモ形式のプログラム。  
当時は全く解き方がわからなかった。  
FSBやunsorted binなど、様々な方法でlibc baseをリークできる。  
## 解法
詳細はexploitのコメントに。  
tcacheを書いて考えるとすごく解きやすかった。  
あと、\__free_hookから発火させる場合は発火に条件があるOneGadgetで書き換えるより、system関数で書き換えて/bin/sh書き込んだchunkを解法させた方が確実だと今更気づいた。  
