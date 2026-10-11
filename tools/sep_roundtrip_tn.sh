# Sepolia side of the public-testnet round trip: certificate -> claim -> burn back to a Solana testnet address.
#   sep_roundtrip_tn.sh <moonlink address> <cert json> <groth16 json> <deposit nonce> <solana recipient (base58)>
export PATH=/root/.foundry/bin:$PATH HOME=/root; R=https://ethereum-sepolia-rpc.publicnode.com
PK=$(python3 -c "import json;d=json.load(open('/root/sepolia.json'))['data'];d=d[0] if isinstance(d,list) else d;print(d['private_key'])")
ME=0x07d0c7C74F83cE5614E44913203856a0A4b67FdE; M=$1; J=$2; G=$3; NONCE=$4
q() { python3 -c "import json,sys;print(json.load(open('$1'))$2)"; }
SOL32=$(python3 -c "import base58;print('0x'+base58.b58decode('$5').hex())")
tx() { cast send --rpc-url $R --private-key $PK $M "$@" --json | python3 -c "import json,sys;r=json.load(sys.stdin);print('  tx', r['transactionHash'], 'block', int(r['blockNumber'],16), 'status', r['status'], 'gas', int(r['gasUsed'],16))"; }
SLOT=$(q $J "['slot']"); BID=$(q $J "['blockId']"); PKS=$(q $J "['pks']"); STAKES=$(q $J "['stakes']" | tr -d "' ")
SIG=$(q $J "['sig0']"); BITS=$(q $J "['bits0']" | tr -d "' ")
echo "epochOf($SLOT) = $(cast call --rpc-url $R $M 'epochOf(uint64)(uint64)' $SLOT)"
[ "$(cast call --rpc-url $R $M 'finalizedBlock(uint64)(bytes32)' $SLOT)" = "$BID" ] || { echo submitCertificate; tx "submitCertificate(uint64,bytes32,bytes,uint256[],(bytes,uint256[])[])" $SLOT $BID $PKS "$STAKES" "[($SIG,$BITS)]"; }
[ "$(cast call --rpc-url $R $M 'claimed(uint64)(bool)' $NONCE)" = "true" ] || { echo claim; tx "claim(bytes,bytes)" $(q $G "['publicValues']") $(q $G "['proof']"); }
echo "wrapped balance: $(cast call --rpc-url $R $M 'balanceOf(address)(uint256)' $ME)"
[ "$(cast call --rpc-url $R $M 'burnCount()(uint64)')" != "0" ] || { echo burn; tx "burn(uint64,bytes32)" 1000000000 $SOL32; }
echo "after burn: balance $(cast call --rpc-url $R $M 'balanceOf(address)(uint256)' $ME), burns(0) = $(cast call --rpc-url $R $M 'burns(uint64)(bytes32)' 0)"
echo "sepolia block $(cast block-number --rpc-url $R)"
