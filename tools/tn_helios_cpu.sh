# Build and run the SP1 Helios Groth16 proofs on CPU (no GPU), from tn_helios_fixture.sh's cbor.
. /root/.cargo/env; export PATH=/usr/local/go/bin:/root/.sp1/bin:$PATH
cp /mnt/c/Users/rapha/moonlink/helios/ml_prove.rs /root/sp1-helios/script/bin/ml_prove.rs
cd /root/sp1-helios && SP1_SKIP_PROGRAM_BUILD=true cargo build --release -p sp1-helios-script --bin ml_prove --features mlcpu 2>&1 | grep -E "^error|Finished" | tail -5
mkdir -p /root/tn/helios && RUST_LOG=info /usr/bin/time -v ./target/release/ml_prove /root/tn/sepolia_tn.cbor /root/tn/helios > /root/tn/helios/ml.log 2>&1
echo "ml_prove exit $?"; grep -E "executed|groth16 proof|Elapsed|Maximum resident" /root/tn/helios/ml.log; ls -la /root/tn/helios
