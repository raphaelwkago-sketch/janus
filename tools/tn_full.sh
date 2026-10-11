# Re-download the testnet full snapshot whose base slot is $1 (the incremental in ledger/remote builds on it).
BASE=$1; OUT=/root/tn/ledger/remote; : > /root/tn/full_dl.log
for r in $(curl -s -m 20 https://api.testnet.solana.com -X POST -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"getClusterNodes"}' | python3 -c "import sys,json;[print(n['rpc']) for n in json.load(sys.stdin)['result'] if n.get('rpc')]"); do
  f=$(curl -s -o /dev/null -m 4 -w "%{redirect_url}" "http://$r/snapshot.tar.bz2")
  case "$f" in */snapshot-$BASE-*)
    n=$(basename "$f"); echo "from $r: $n" >> /root/tn/full_dl.log
    curl -s --speed-limit 1000000 --speed-time 30 -o "$OUT/$n.tmp" "$f" && mv "$OUT/$n.tmp" "$OUT/$n" && { echo DL_DONE >> /root/tn/full_dl.log; exit 0; }
    rm -f "$OUT/$n.tmp"; echo "failed/slow from $r, next" >> /root/tn/full_dl.log;;
  esac
done; echo DL_FAILED >> /root/tn/full_dl.log
