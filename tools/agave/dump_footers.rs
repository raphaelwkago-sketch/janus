// Dump Alpenglow block footers + block ids from a local ledger, as JSON lines.
use {
    solana_entry::block_component::{BlockComponent, VersionedBlockFooter},
    solana_ledger::{blockstore::Blockstore, blockstore_meta::BlockLocation},
    std::path::Path,
};
fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }
fn main() {
    let path = std::env::args().nth(1).expect("ledger path");
    let bs = Blockstore::open(Path::new(&path)).expect("open blockstore");
    let max = bs.highest_slot().unwrap().unwrap_or(0);
    let first: u64 = std::env::args().nth(2).and_then(|s| s.parse().ok()).unwrap_or(0); // optional start slot
    for slot in first..=max {
        let block_id = bs.get_double_merkle_root(slot, BlockLocation::Original).ok().flatten();
        let Ok((components, _, _)) = bs.get_slot_components_with_shred_info(slot, 0, false) else { continue };
        let parent = bs.meta(slot).ok().flatten().and_then(|m| m.parent_slot);
        for c in components {
            let BlockComponent::BlockMarker(m) = c else { continue };
            let solana_entry::block_component::VersionedBlockMarker::V1(m1) = &m;
            let Some(VersionedBlockFooter::V1(f)) = m1.as_block_footer() else { continue };
            let fc = f.block_final_cert.as_ref().map(|fc| {
                format!(
                    "{{\"slot\":{},\"block_id\":\"{}\",\"final\":\"{}\",\"notar\":{}}}",
                    fc.slot,
                    hex(fc.block_id.as_ref()),
                    hex(&wincode::serialize(&fc.final_aggregate).unwrap()),
                    fc.notar_aggregate.as_ref().map(|n| format!("\"{}\"", hex(&wincode::serialize(n).unwrap()))).unwrap_or("null".into())
                )
            }).unwrap_or("null".into());
            println!(
                "{{\"slot\":{slot},\"parent\":{},\"block_id\":{},\"bank_hash\":\"{}\",\"final_cert\":{fc}}}",
                parent.map(|p| p.to_string()).unwrap_or("null".into()),
                block_id.map(|h| format!("\"{}\"", hex(h.as_ref()))).unwrap_or("null".into()),
                hex(f.bank_hash.as_ref()),
            );
        }
    }
}
