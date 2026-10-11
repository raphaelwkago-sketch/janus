# Download the newest testnet incremental snapshot built on our full snapshot (base slot $1) into the ledger.
BASE=$1; OUT=/root/tn/ledger/remote
for r in $(curl -s -m 20 https://api.testnet.solana.com -X POST -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"getClusterNodes"}' | python3 -c "import sys,json;[print(n['rpc']) for n in json.load(sys.stdin)['result'] if n.get('rpc')]"); do
  f=$(curl -s -o /dev/null -m 4 -w "%{redirect_url}" "http://$r/incremental-snapshot.tar.bz2")
  case "$f" in *incremental-snapshot-$BASE-*) n=$(basename "$f"); echo "from $r: $n"; curl -s -m 600 -o "$OUT/$n.tmp" "$f" && mv "$OUT/$n.tmp" "$OUT/$n" && ls -la "$OUT/$n" && exit 0;; esac
done; echo "no incremental on base $BASE found"; exit 1
