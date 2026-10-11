# Wait until Sepolia finalizes the burn block, then build the SP1 Helios input (light client + burn storage slot).
#   tn_helios_fixture.sh <moonlink address> <burn block> <storage key> <out.cbor> [bootstrap slot]
export PATH=/root/.foundry/bin:$PATH
until [ "$(cast block finalized --rpc-url https://ethereum-sepolia-rpc.publicnode.com -f number 2>/dev/null || echo 0)" -ge "$2" ]; do sleep 30; done
echo "burn block $2 finalized"
cd /root/sp1-helios && ./target/release/gen_fixture --source-consensus-rpc http://unstable.sepolia.beacon-api.nimbus.team \
  --source-execution-rpc https://sepolia.rpc.thirdweb.com --source-chain-id 11155111 ${5:+--bootstrap-slot $5} \
  --storage-contract $1 --storage-key $3 --output $4 2>&1 | grep -vE "DEBUG|TRACE" | tail -5
ls -la $4
