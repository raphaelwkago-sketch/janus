# One-line status of the testnet snapshot download + replay (for monitoring).
if pgrep -x agave-ledger-to >/dev/null; then s=running; else s=idle; fi
d=$(grep -c "deleted unpacked" /root/tn/replay.log)
e=$(grep -E "verify exit" /root/tn/replay.log | tail -1)
dl=$(tail -1 /root/tn/full_dl.log | cut -c1-12)
p=$(ls -la /root/tn/ledger/remote/ 2>/dev/null | awk '/snapshot-.*tmp/{printf "%d", $5/1e9}')
echo "dl=$dl ${p}GB | replay $s archive_deleted=$d $e"
