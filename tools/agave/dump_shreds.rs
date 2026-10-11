// Dump raw data shreds of given slots (plus Agave's own FEC roots / block id for cross-checking), as JSON lines.
use {solana_ledger::{blockstore::Blockstore, blockstore_meta::BlockLocation}, std::path::Path};
fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }
fn main() {
    let mut a = std::env::args().skip(1);
    let bs = Blockstore::open(Path::new(&a.next().expect("ledger"))).expect("open");
    for s in a {
        let slot: u64 = s.parse().unwrap();
        let parent = bs.meta(slot).ok().flatten().and_then(|m| m.parent_slot);
        let bid = |x: u64| bs.get_double_merkle_root(x, BlockLocation::Original).ok().flatten().map(|h| format!("\"{}\"", hex(h.as_ref()))).unwrap_or("null".into());
        let shreds = bs.get_data_shreds_for_slot(slot, 0).expect("shreds");
        let items: Vec<String> = shreds.iter().map(|sh| format!(
            "{{\"i\":{},\"fec\":{},\"root\":\"{}\",\"last\":{},\"complete\":{},\"hex\":\"{}\"}}",
            sh.index(), sh.fec_set_index(), hex(sh.merkle_root().unwrap().as_ref()), sh.last_in_slot(), sh.data_complete(), hex(&sh.payload()[..])
        )).collect();
        println!("{{\"slot\":{slot},\"parent\":{},\"block_id\":{},\"parent_block_id\":{},\"shreds\":[{}]}}",
            parent.map(|p| p.to_string()).unwrap_or("null".into()), bid(slot), parent.map(bid).unwrap_or("null".into()), items.join(","));
    }
}
