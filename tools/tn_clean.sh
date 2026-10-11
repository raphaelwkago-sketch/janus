# Free disk after the testnet round trip. Keeps keypairs and small results.
set -e
mkdir -p /root/keys
cp -n /root/tn/payer.json /root/tn/moonlink_prog.json /root/tn/recorder_prog.json /root/keys/
cp -n /root/tn/deposit_1.json /root/tn/proof_450906700.json /root/tn/sepolia_tn.cbor /root/tn/sep_moonlink_tn2 /root/keys/ 2>/dev/null || true
rm -rf /root/tn /root/agave44 /root/agave-src/target
rm -rf /root/mc2/v1 /root/mc2/v2 /root/mc2/v3 /root/mc2/v4 /root/mc2/slots.json /root/mc2/genesis
ls /root/keys
df -h / | tail -1
fstrim -v /
