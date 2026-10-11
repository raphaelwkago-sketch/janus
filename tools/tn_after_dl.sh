# Wait for the full snapshot download, then replay testnet slot $1.
until grep -qE "DL_DONE|DL_FAILED" /root/tn/full_dl.log; do sleep 10; done
grep -q DL_DONE /root/tn/full_dl.log || { echo "download failed" > /root/tn/replay.log; echo "verify exit 99" >> /root/tn/replay.log; exit 1; }
rm -f /root/tn/slots.json
bash /mnt/c/Users/rapha/moonlink/tools/tn_replay.sh $1
