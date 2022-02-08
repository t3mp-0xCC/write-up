# beginners heap
https://bitbucket.org/ptr-yudai/writeups-2020/src/master/SECCON_Beginners_CTF_2020/beginners_heap/  
## 概要  
ヒープオーバーフローの脆弱性を使ってUseAfterFreeおよびチャンクのサイズ改変をする事で`__free_hook`に`win`関数を書き込む。  
ヒープを可視化する機能や、tcacheを視覚的に表示する機能が備わっているので、勉強しながら解ける。  
## 解法  
ユーザーが操作する前に既にチャンクA(size = 0x18)が確保されており、ユーザーは以下の操作ができる。  
1. チャンクAに対する書き込み(0x80バイト)
2. チャンクBをmalloc(size = 0x18)して0x18バイトの書き込み  
3. チャンクBをfree  

他にもチャンクA周りのヒープを表示したり、tcacheのリンクを表示したり、進行度にあったヒントを表示する機能がある。  
本当にすごい。  
また、libc上の`__free_hook`のアドレスと、flagを出力する`win`関数のアドレスを最初に与えられる。  
Aのチャンクが0x18バイトであるのに対して書き込みが0x80バイトできてしまうことから、自明なヒープオーバーフローの脆弱性が存在する。  
これをうまく使うにはAよりも高位のアドレスにチャンクを確保する必要があるので、2を選択してチャンクBをmallocし、freeする。  
(このBはtcacheに繋がれる。)  
tcacheに入ったチャンクは以下のような構造になっている。  
```
+---------------------+
|  size & some flag   |
+---------------------+
| fd(next chunk addr) |
+---------------------+
|   ..............    |
```  
よってfd部分に`__free_hook`のアドレスを書き込めば、チャンクBをmallocした後に　`__free_hook`をmallocして書き換える事ができる。  
しかしここでmallocの回数が問題になる。  
操作としてはチャンクBを一度のみmallocする事しかできないので、2回連続でmallocする事ができない。  
そこで、fdと同様にsizeを書き換える。  
例えばsizeを0x30に書き換えた場合、チャンクBは**size=0x30用のtcacheに繋がれる。**  
mallocする際のsizeは0x18で固定されているので、この場合はチャンクBが再びmallocされるのではなく(sizeが異なるため)、`__free_hook`がmallocされる(こっちのsizeは0x18なのでサイズが合う)。  
結果として、以下の操作を行えば`__free_hook`をmallocできる。  
1. Bをmalloc
2. Bをfree
3. Aでオーバーフローを起こし、sizeを改変、fdには`_free_hook`を書き込む
4. Bをmalloc&free(0x18とは異なるサイズのtcacheに繋がれる)    
5. Bをmalloc(これで`__free_hook`がmallocされる)  

あとはBに書き込む際に`win`関数のアドレスを書き込めばflagが表示される。  