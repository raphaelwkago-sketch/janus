# Re-run the CPU Helios proofs with fewer SP1 workers (lower peak memory) after an out-of-memory kill.
export SP1_WORKER_NUM_CORE_WORKERS=1 SP1_WORKER_CORE_BUFFER_SIZE=1 SP1_WORKER_NUM_SPLICING_WORKERS=1 SP1_WORKER_SPLICING_BUFFER_SIZE=1 \
  SP1_WORKER_NUM_RECURSION_EXECUTOR_WORKERS=2 SP1_WORKER_NUM_PREPARE_REDUCE_WORKERS=2 SP1_WORKER_NUM_SETUP_WORKERS=1
export PATH=/usr/local/go/bin:/root/.sp1/bin:$PATH
cd /root/sp1-helios && RUST_LOG=info /usr/bin/time -v ./target/release/ml_prove /root/tn/sepolia_tn.cbor /root/tn/helios > /root/tn/helios/ml.log 2>&1
echo "ml_prove exit $?"; grep -E "executed|groth16 proof|Elapsed|Maximum resident|signal" /root/tn/helios/ml.log; ls -la /root/tn/helios
