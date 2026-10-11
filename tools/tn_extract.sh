# Dump block data for slot $1 from the testnet ledger and replay it from the snapshot (patched ledger-tool).
G=$1; T=/root/tn; E=/root/agave44/target/release/examples; LT=/root/agave44/dev-bins/target/release/agave-ledger-tool
$E/dump_footers $T/ledger $((G-300)) > $T/footers.jsonl; echo "footers: $(wc -l < $T/footers.jsonl)"
$E/dump_shreds $T/ledger $(seq $((G-3)) $G) > $T/shreds.jsonl; echo "shreds.jsonl: $(wc -c < $T/shreds.jsonl) bytes"
rm -f $T/slots.json
/usr/bin/time -f "replay %e s, %M KB peak" $LT verify --ledger $T/ledger \
  --full-snapshot-archive-path $T/ledger/remote --incremental-snapshot-archive-path $T/ledger/remote \
  --halt-at-slot $((G+2)) --record-slots $T/slots.json --record-slots-config accounts > $T/replay.log 2>&1; echo "verify exit $?"
tail -2 $T/replay.log | cut -c1-200; grep -iE "panic|mismatch|error" $T/replay.log | head -3 | cut -c1-250
ls -la $T/slots.json
