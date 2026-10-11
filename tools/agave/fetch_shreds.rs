//! Fetch whole blocks from a public cluster over the repair protocol (no inbound ports needed: repair
//! responses come back to the request's source address), and insert them into a local blockstore so
//! agave-ledger-tool can replay them from a snapshot. Answers the repair servers' anti-spoof pings.
//!   fetch_shreds <identity.json> <ledger dir> <peers file: "pubkey ip:port" per line> <slots file: one slot per line>
use {
    solana_core::repair::serve_repair::{RepairProtocol, RepairRequestHeader, ServeRepair},
    solana_gossip::ping_pong::{Ping, Pong},
    solana_keypair::{read_keypair_file, Keypair},
    solana_ledger::{blockstore::Blockstore, shred::Shred},
    solana_pubkey::Pubkey,
    solana_signer::Signer,
    std::{
        collections::{HashMap, HashSet},
        net::{SocketAddr, UdpSocket},
        path::Path,
        str::FromStr,
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    },
};

struct Want { last: Option<u32>, have: HashSet<u32> }

fn now_ms() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64 }

fn request(kp: &Keypair, peer: &(Pubkey, SocketAddr), slot: u64, idx: u64, highest: bool, nonce: u32) -> Vec<u8> {
    let header = RepairRequestHeader::new(kp.pubkey(), peer.0, now_ms(), nonce);
    let req = if highest {
        RepairProtocol::HighestWindowIndex { header, slot, shred_index: idx }
    } else {
        RepairProtocol::WindowIndex { header, slot, shred_index: idx }
    };
    ServeRepair::repair_proto_to_bytes(&req, kp).unwrap()
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let kp = read_keypair_file(&a[1]).unwrap();
    let bs = Blockstore::open(Path::new(&a[2])).unwrap();
    let peers: Vec<(Pubkey, SocketAddr)> = std::fs::read_to_string(&a[3]).unwrap().lines()
        .filter_map(|l| { let mut it = l.split_whitespace(); Some((Pubkey::from_str(it.next()?).ok()?, it.next()?.parse().ok()?)) })
        .collect();
    let slots: Vec<u64> = std::fs::read_to_string(&a[4]).unwrap().lines().filter_map(|l| l.trim().parse().ok()).collect();
    let mut want: HashMap<u64, Want> = slots.iter().map(|s| (*s, Want { last: None, have: HashSet::new() })).collect();
    // shreds already in the blockstore count as fetched
    for (s, w) in want.iter_mut() {
        if let Ok(meta) = bs.meta(*s) { if let Some(m) = meta {
            if m.is_full() { w.last = m.last_index.map(|x| x as u32); w.have = (0..=w.last.unwrap()).collect(); }
        }}
    }
    let sock = UdpSocket::bind("0.0.0.0:0").unwrap();
    sock.set_read_timeout(Some(Duration::from_millis(5))).unwrap();
    println!("{} peers, {} slots, socket {}", peers.len(), slots.len(), sock.local_addr().unwrap());
    let (mut sent, mut got, mut pings, mut pi, mut nonce) = (0u64, 0u64, 0u64, 0usize, 1u32);
    let start = Instant::now();
    let mut buf = [0u8; 2048];
    loop {
        let open: Vec<u64> = { let mut v: Vec<u64> = want.iter().filter(|(_, w)| w.last.map_or(true, |l| w.have.len() < l as usize + 1)).map(|(s, _)| *s).collect(); v.sort(); v };
        if open.is_empty() || start.elapsed() > Duration::from_secs(1800) { break; }
        let mut budget = 4000;
        for s in &open {
            let w = &want[s];
            let idxs: Vec<u64> = match w.last {
                None => vec![u64::MAX],                       // ask for the last shred first
                Some(l) => (0..=l).filter(|i| !w.have.contains(i)).map(u64::from).take(64).collect(),
            };
            for i in idxs {
                for _ in 0..if i == u64::MAX { 3 } else { 1 } {
                    let p = &peers[pi % peers.len()]; pi += 1; nonce = nonce.wrapping_add(1);
                    let pkt = if i == u64::MAX { request(&kp, p, *s, 0, true, nonce) } else { request(&kp, p, *s, i, false, nonce) };
                    let _ = sock.send_to(&pkt, p.1); sent += 1; budget -= 1;
                }
            }
            if budget <= 0 { break; }
        }
        let t = Instant::now(); let mut batch = Vec::new();
        while t.elapsed() < Duration::from_millis(400) {
            let Ok((n, from)) = sock.recv_from(&mut buf) else { continue };
            if n == 4 + 32 + 32 + 64 && buf[..4] == [0, 0, 0, 0] {
                if let Ok(ping) = wincode::deserialize::<Ping<32>>(&buf[4..n]) {
                    let pong = RepairProtocol::Pong(Pong::new(&ping, &kp));
                    let _ = sock.send_to(&wincode::serialize(&pong).unwrap(), from); pings += 1; continue;
                }
            }
            if n <= 4 { continue; }
            let Ok(sh) = Shred::new_from_serialized_shred(buf[..n - 4].to_vec()) else { continue };
            if !sh.is_data() { continue; }
            let Some(w) = want.get_mut(&sh.slot()) else { continue };
            if sh.last_in_slot() { w.last = Some(sh.index()); }
            if w.have.insert(sh.index()) { got += 1; batch.push(sh); }
        }
        if !batch.is_empty() { let k = batch.len(); bs.insert_shreds(batch, false).unwrap(); let _ = k; }
        let done = want.values().filter(|w| w.last.map_or(false, |l| w.have.len() == l as usize + 1)).count();
        println!("t={:>4}s sent {sent} got {got} pings {pings} complete slots {done}/{}", start.elapsed().as_secs(), want.len());
    }
    let mut missing: Vec<u64> = want.iter().filter(|(_, w)| w.last.map_or(true, |l| w.have.len() < l as usize + 1)).map(|(s, _)| *s).collect();
    missing.sort();
    println!("DONE complete {}/{} missing {:?}", want.len() - missing.len(), want.len(), &missing[..missing.len().min(20)]);
}
