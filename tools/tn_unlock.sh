# Testnet: init + update the Solana-side Ethereum light client, then unlock deposit 0.
export RPC=https://api.testnet.solana.com PROGRAM=Ftazryb4STB7rV4xHsYE5E52VZrYtkfPFw2ZXEAfcuJv PAYER=/root/tn/payer.json
S=/mnt/c/Users/rapha/moonlink/tools/soleth.py
cd /root
python3 $S init /root/tn/helios/lc.json 0x5ad9be60031c564ce135f3e5596e357bea47e106 2>&1 | tail -4; echo ---
python3 $S update /root/tn/helios/lc.json 2>&1 | tail -4; echo ---
python3 $S unlock /root/tn/helios/st.json 11327616 1000000000 0 2X4UNgpuV4LJpz2vAodsjzTNhoQ54xubT2UTuGh8NfKY 2>&1 | tail -4
