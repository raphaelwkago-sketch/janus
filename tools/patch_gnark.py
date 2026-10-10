# The upstream repo github.com/consensys/gnark-ignition-verifier is gone. It is only used to rebuild the
# PLONK SRS (circuit build time), never for proving with SP1's published Groth16 artifacts. Stub that function.
import glob, re
f = glob.glob("/root/.cargo/registry/src/*/sp1-recursion-gnark-ffi-6.8.1/go/sp1/trusted_setup/trusted_setup.go")[0]
s = open(f).read()
if "ignition\"" in s:
    s = s.replace('\t"github.com/consensys/gnark-ignition-verifier/ignition"\n', "")
    a = s.index("func DownloadAndSaveAztecIgnitionSrs")
    b = s.index("\n}\n", a) + 3
    s = s[:a] + 'func DownloadAndSaveAztecIgnitionSrs(startIdx int, fileName string) {\n\tlog.Fatal("ignition SRS download disabled (upstream repo removed)")\n}\n' + s[b:]
    if "bn254." not in s.replace("kzg_bn254.", ""):
        s = s.replace('\t"github.com/consensys/gnark-crypto/ecc/bn254"\n', "")
    if "os." not in s:
        s = s.replace('\t"os"\n', "")
    open(f, "w").write(s)
print("patched", f)
