# Round trip on Sepolia with node-side gas estimation (new state-creation pricing).
export PATH=/root/.foundry/bin:$PATH HOME=/root; R=https://ethereum-sepolia-rpc.publicnode.com
cd /root/moonlink-eth
PK=$(python3 -c "import json;d=json.load(open('/root/sepolia.json'))['data'];d=d[0] if isinstance(d,list) else d;print(d['private_key'])")
ME=0x07d0c7C74F83cE5614E44913203856a0A4b67FdE
J=test/fixtures/cert_3348.json; G=test/fixtures/groth16_3348.json
q() { python3 -c "import json,sys;print(json.load(open('$1'))$2)"; }
deploy() { # $1 initcode -> prints address
  cast send --rpc-url $R --private-key $PK --create "$1" --json | python3 -c "import json,sys;r=json.load(sys.stdin);print(r['contractAddress'], 'status', r['status'], 'gas', int(r['gasUsed'],16), file=sys.stderr);print(r['contractAddress'])"; }
V=$(cat /root/sep_verifier 2>/dev/null)
if [ -z "$V" ]; then V=$(deploy $(forge inspect src/sp1/v6.1.0/SP1VerifierGroth16.sol:SP1Verifier bytecode)); echo $V > /root/sep_verifier; fi
echo "verifier $V"
PKS=$(q $J "['pks']"); STAKES=$(q $J "['stakes']" | tr -d "' "); SV=$(q $J "['sv']"); EP=$(q $J "['epoch']")
VK=$(q $G "['vkey']")
ARGS=$(cast abi-encode "f(uint16,uint64,uint64,bytes,uint256[],address,bytes32,bytes32,bytes32)" $SV 200 $EP $PKS "$STAKES" $V $VK 0xd71dec929591a91ff4c4199baa018069b1f79ccd1d1bf2a5d67c2f39d447eb5d 0x0000000000000000000000000000000000000000000000000000000000000002)
M=$(cat /root/sep_moonlink 2>/dev/null)
if [ -z "$M" ]; then M=$(deploy $(forge inspect src/Moonlink.sol:Moonlink bytecode)${ARGS:2}); echo $M > /root/sep_moonlink; fi
echo "moonlink $M"
SLOT=$(q $J "['slot']"); BID=$(q $J "['blockId']"); SIG=$(q $J "['sig0']"); BITS=$(q $J "['bits0']" | tr -d "' ")
tx() { cast send --rpc-url $R --private-key $PK $M "$@" --json | python3 -c "import json,sys;r=json.load(sys.stdin);print('  tx', r['transactionHash'], 'status', r['status'], 'gas', int(r['gasUsed'],16))"; }
[ "$(cast call --rpc-url $R $M 'finalizedBlock(uint64)(bytes32)' $SLOT)" = "$BID" ] || { echo submitCertificate; tx "submitCertificate(uint64,bytes32,bytes,uint256[],(bytes,uint256[])[])" $SLOT $BID $PKS "$STAKES" "[($SIG,$BITS)]"; }
[ "$(cast call --rpc-url $R $M 'claimed(uint64)(bool)' 8)" = "true" ] || { echo claim; tx "claim(bytes,bytes)" $(q $G "['publicValues']") $(q $G "['proof']"); }
echo "wrapped balance: $(cast call --rpc-url $R $M 'balanceOf(address)(uint256)' $ME)"
[ "$(cast call --rpc-url $R $M 'burnCount()(uint64)')" != "0" ] || { echo burn; tx "burn(uint64,bytes32)" 1000000000 0xa4fb8b7dd9588255bafe411de8f4de53603511a5266386e74ef3c96a5e31129f; }
echo "after burn: balance $(cast call --rpc-url $R $M 'balanceOf(address)(uint256)' $ME), burns(0) = $(cast call --rpc-url $R $M 'burns(uint64)(bytes32)' 0)"
cast block-number --rpc-url $R
