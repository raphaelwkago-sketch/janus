# Deploy a Moonlink contract on Sepolia that trusts Solana TESTNET (Alpenglow) from a recorded epoch set.
#   sep_deploy_tn.sh <set json with epoch, setHash, total> <deposit program> <recorder program> <groth16 json (program vkey)>
export PATH=/root/.foundry/bin:$PATH HOME=/root; R=https://ethereum-sepolia-rpc.publicnode.com
cd /root/moonlink-eth
PK=$(python3 -c "import json;d=json.load(open('/root/sepolia.json'))['data'];d=d[0] if isinstance(d,list) else d;print(d['private_key'])")
S=$1; q() { python3 -c "import json;print(json.load(open('$S'))$1)"; }
b32() { python3 -c "import base58,sys;print('0x'+base58.b58decode('$1').hex())"; }
V=$(cat /root/sep_verifier); VK=$(python3 -c "import json;print(json.load(open('$4'))['vkey'])")
ARGS=$(cast abi-encode "f(uint16,uint64,bool,uint64,bytes32,uint256,address,bytes32,bytes32,bytes32)" 4457 432000 true $(q "['epoch']") $(q "['setHash']") $(q "['total']") $V $VK $(b32 $2) $(b32 $3))
forge build -q
cast send --rpc-url $R --private-key $PK --create $(forge inspect src/Moonlink.sol:Moonlink bytecode)${ARGS:2} --json | python3 -c "import json,sys;r=json.load(sys.stdin);print('Moonlink (testnet)', r['contractAddress'], 'status', r['status'], 'gas', int(r['gasUsed'],16))"
