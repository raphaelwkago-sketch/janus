// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {MoonlinkLightClient} from "./MoonlinkLightClient.sol";
import {AlpenglowBLS} from "./AlpenglowBLS.sol";

interface ISP1Verifier {
    function verifyProof(bytes32 programVKey, bytes calldata publicValues, bytes calldata proofBytes) external view;
}

/// Moonlink, Ethereum side. Trust comes only from Solana's own validators:
///  - submitCertificate: BLS finalization certificate (checked here, EIP-2537) -> block is final
///  - claim: SP1 proof that the final block created Moonlink receipts -> mint wrapped SOL
///  - installNextSet: SP1 proof of the recorder's validator list for the new epoch, accepted only if
///    the certificate of that block is also signed by >= 60% of the PREVIOUS epoch's stake
contract Moonlink is MoonlinkLightClient {
    struct Receipt { address eth; uint64 amount; uint64 nonce; }
    struct PublicValues { uint64 slot; bytes32 blockId; bytes32 program; Receipt[] receipts; }
    struct SetValues { uint64 slot; bytes32 blockId; bytes32 program; uint64 epoch; bytes32 setHash; uint256 totalStake; uint32 count; }

    ISP1Verifier public immutable verifier;
    bytes32 public immutable programVKey;     // the Moonlink SP1 program (fixed code)
    bytes32 public immutable depositProgram;  // Solana deposit program id
    bytes32 public immutable recorderProgram; // Solana validator-set recorder program id
    uint256 public constant HANDOFF_PCT = 60;

    mapping(uint64 => bool) public claimed;   // deposit nonce -> paid
    mapping(address => uint256) public balanceOf; // wrapped SOL (9 decimals, = lamports)
    uint256 public totalSupply;
    // ETH -> SOL: burns are written to storage so Solana can prove them with an Ethereum storage proof
    // (SP1 Helios light client). Storage slot of burns[n] = keccak256(abi.encode(n, BURNS_SLOT)).
    uint64 public burnCount;
    mapping(uint64 => bytes32) public burns;  // burn nonce -> keccak256(solRecipient | amount u64 BE | nonce u64 BE)
    uint256 public constant BURNS_SLOT = 6;

    event Claimed(uint64 indexed nonce, address indexed to, uint64 amount);
    event Burned(uint64 indexed nonce, address indexed from, bytes32 solRecipient, uint64 amount);
    event SetInstalled(uint64 indexed epoch, bytes32 setHash, uint256 totalStake, uint256 handoffStake);

    error NotFinalized();
    error WrongProgram();
    error AlreadyClaimed(uint64 nonce);
    error BadEpoch();
    error SignerKeyMismatch(uint256 newRank);
    error HandoffTooLow(uint256 covered, uint256 oldTotal);
    error MissingPop(uint256 newRank);
    error BadBurn();

    constructor(
        uint16 shredVersion_, uint64 slotsPerEpoch_, bool warmup_, uint64 epoch, bytes32 setHash, uint256 totalStake,
        ISP1Verifier verifier_, bytes32 programVKey_, bytes32 depositProgram_, bytes32 recorderProgram_
    ) MoonlinkLightClient(shredVersion_, slotsPerEpoch_, warmup_, epoch, setHash, totalStake) {
        verifier = verifier_;
        programVKey = programVKey_;
        depositProgram = depositProgram_;
        recorderProgram = recorderProgram_;
    }

    function claim(bytes calldata publicValues, bytes calldata proof) external {
        verifier.verifyProof(programVKey, publicValues, proof);
        PublicValues memory pv = abi.decode(publicValues, (PublicValues));
        if (pv.program != depositProgram) revert WrongProgram();
        if (finalizedBlock[pv.slot] != pv.blockId || pv.blockId == bytes32(0)) revert NotFinalized();
        for (uint256 i = 0; i < pv.receipts.length; i++) {
            Receipt memory r = pv.receipts[i];
            if (claimed[r.nonce]) revert AlreadyClaimed(r.nonce);
            claimed[r.nonce] = true;
            balanceOf[r.eth] += r.amount;
            totalSupply += r.amount;
            emit Claimed(r.nonce, r.eth, r.amount);
        }
    }

    /// Burn wrapped SOL here to unlock the same lamports from the vault on Solana.
    function burn(uint64 amount, bytes32 solRecipient) external returns (uint64 nonce) {
        if (amount == 0 || solRecipient == bytes32(0) || balanceOf[msg.sender] < amount) revert BadBurn();
        balanceOf[msg.sender] -= amount;
        totalSupply -= amount;
        nonce = burnCount++;
        burns[nonce] = keccak256(abi.encodePacked(solRecipient, amount, nonce));
        emit Burned(nonce, msg.sender, solRecipient, amount);
    }

    struct Handoff {
        bytes pksOld;
        uint256[] stakesOld;
        uint256[] oldIndexOfNewRank; // 1 + index in old set of the validator at new rank j (0 = new validator)
        bytes[] popPayload;          // per new rank: "ALPENGLOW"|vote pubkey, required for NEW validators that signed
        bytes[] popSig;              // per new rank: 256-byte G2 proof of possession
    }

    /// Install the validator set of epoch s.epoch, proven from the recorder account on Solana.
    function installNextSet(
        bytes calldata setPublicValues,
        bytes calldata proof,
        bytes calldata pksNew,
        uint256[] calldata stakesNew,
        Agg[] calldata aggs,
        Handoff calldata h
    ) external {
        verifier.verifyProof(programVKey, setPublicValues, proof);
        SetValues memory s = abi.decode(setPublicValues, (SetValues));
        if (s.program != recorderProgram) revert WrongProgram();
        if (epochOf(s.slot) != s.epoch || sets[s.epoch].hash != bytes32(0)) revert BadEpoch();
        ValidatorSet memory old = sets[s.epoch - 1];
        if (old.hash == bytes32(0)) revert UnknownEpoch(s.epoch - 1);
        if (keccak256(abi.encode(h.pksOld, h.stakesOld)) != old.hash) revert WrongSet();

        // the block holding the record must carry a valid certificate under the NEW set ...
        ValidatorSet memory nv = ValidatorSet(s.setHash, s.totalStake);
        _verifyCert(s.slot, s.blockId, nv, pksNew, stakesNew, aggs);
        // ... whose signers also hold >= 60% of the OLD epoch's stake (keys matched one by one),
        // and every NEW signer proves possession of its key (blocks rogue-key forgeries)
        uint256 covered = type(uint256).max;
        for (uint256 a = 0; a < aggs.length; a++) {
            uint256 c = _covered(pksNew, aggs[a].bits, h);
            if (c < covered) covered = c;
        }
        if (covered * 100 < old.totalStake * HANDOFF_PCT) revert HandoffTooLow(covered, old.totalStake);

        sets[s.epoch] = nv;
        finalizedBlock[s.slot] = s.blockId;
        emit SetInstalled(s.epoch, s.setHash, s.totalStake, covered);
    }

    function _covered(bytes calldata pksNew, uint256[] calldata bits, Handoff calldata h)
        internal view returns (uint256 covered)
    {
        uint256 n = pksNew.length / 128;
        for (uint256 j = 0; j < n; j++) {
            if ((bits[j >> 8] >> (j & 255)) & 1 == 0) continue;
            bytes calldata pk = pksNew[j * 128:(j + 1) * 128];
            if (h.oldIndexOfNewRank[j] == 0) {
                if (h.popSig[j].length != 256 || !AlpenglowBLS.verifyPop(pk, h.popPayload[j], h.popSig[j])) revert MissingPop(j);
                continue;
            }
            uint256 o = h.oldIndexOfNewRank[j] - 1;
            if (keccak256(pk) != keccak256(h.pksOld[o * 128:(o + 1) * 128])) revert SignerKeyMismatch(j);
            covered += h.stakesOld[o];
        }
    }
}
