# stegorop
## 概要
flagが格納されているアドレスが渡されるので、fastbinで遊んでどうにか取り出そうというもの。   
## 解法
fastbinはdouble free対策で連続して同じチャンクをfreeできないようである。  
しかし調べた限りでは、それにさえ気をつければ解法は複数存在するっぽい。  
今回はAをfreeした後にBを挟んでもう一度AをfreeしてAとBを交互に無限に連ならせ、Cをmallocする事でAをmalloc、Cにflagのアドレスを書き込み、flagをmallocするまでCをmallocし続ける事でflagを得ている。  
図で書くと以下のような感じ。  
1. fastbin -> A
2. fastbin -> B -> A
3. fastbin -> A -> B -> A -> B -> A...  
(Aをfreeしたので先頭に追加、しかしBの次はAなので無限に連なる)
4. fastbin -> B -> A -> B -> A -> B...  
(Cをmalloc、先頭のAは外れる。)
5. fastbin -> B -> A -> flag  
(Cにflagのアドレスを書き込む)
6. fastbin -> flag  
(malloc * 2の後の図、これでmallocするとflagがmallocされる。)
