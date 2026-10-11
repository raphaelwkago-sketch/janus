# Replay testnet slot $1 from the local snapshot with the patched ledger-tool, recording bank hash details.
# Deletes the full snapshot archive once it is unpacked (disk is tight); re-download it if a replay must be redone.
T=/root/tn; G=$1; LT=/root/agave44/dev-bins/target/release/agave-ledger-tool
: > $T/replay.log
( $LT verify --ledger $T/ledger --full-snapshot-archive-path $T/ledger/remote --incremental-snapshot-archive-path $T/ledger/remote \
    --halt-at-slot $((G+2)) --record-slots $T/slots.json --record-slots-config accounts >> $T/replay.log 2>&1
  echo "verify exit $?" >> $T/replay.log ) &
while kill -0 $! 2>/dev/null; do
  if grep -qE "Loaded bank|processing ledger from slot|Processing ledger from slot|bank_forks_from_snapshot" $T/replay.log && ls $T/ledger/remote/snapshot-*.tar.zst >/dev/null 2>&1; then
    rm -f $T/ledger/remote/snapshot-*.tar.zst; echo "deleted unpacked full archive" >> $T/replay.log
  fi
  sleep 10
done
