mod crypto;
mod protocol;
use crypto::*;
use protocol::*;
use curve25519_dalek_ng::scalar::Scalar;
use ed25519_dalek::{Signer, SigningKey, Verifier};
use rand::{rngs::OsRng, Rng};
use serde_json::json;
use std::collections::HashMap;
use std::time::Instant;

fn genesis(p: &Params, b: &Bank) -> AccountState {
    let rho = Scalar::random(&mut OsRng);
    AccountState { pk: b.enc.pk, vk: b.sig.verifying_key(), avail: Ct { c: Scalar::from(b.balance) * p.g() + rho * p.h(), d: rho * b.enc.pk },
        pending: Ct::zero(), nonce: 0 }
}
fn stats(v: &[f64]) -> serde_json::Value {
    let mut s = v.to_vec(); s.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let m = s.iter().sum::<f64>() / s.len() as f64;
    let sd = (s.iter().map(|x| (x - m).powi(2)).sum::<f64>() / s.len() as f64).sqrt();
    json!({"mean": m, "sd": sd, "p50": s[s.len()/2], "p95": s[(s.len() as f64 * 0.95) as usize], "n": s.len()})
}
fn rand_amount(rng: &mut impl Rng) -> u64 { // log-uniform between 1e2 and 1e12 minor units
    let e: f64 = rng.gen_range(2.0..12.0); 10f64.powf(e) as u64
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let iters: usize = args.get(1).map(|s| s.parse().unwrap()).unwrap_or(100);
    let out = args.get(2).cloned().unwrap_or("crypto_bench.json".into());
    let p = Params::new();
    let mut rng = rand::thread_rng();
    let t0 = Instant::now(); let bsgs = Bsgs::new(&p, 18); let bsgs_build_s = t0.elapsed().as_secs_f64();
    let committee = committee_setup(&p, 5, 3);
    let pk_a = committee.pk_a;
    let start_bal = 1u64 << 50;
    let mut banks: Vec<Bank> = (0..4).map(|i| Bank::new(&p, i, start_bal)).collect();
    let mut ledger: HashMap<u32, AccountState> = banks.iter().map(|b| (b.id, genesis(&p, b))).collect();

    // ---------------- correctness and security tests ----------------
    let mut tests = serde_json::Map::new();
    let tx = create_tx(&p, &banks[0], &ledger[&0], &ledger[&1].pk, &pk_a, 1, 123_456_789_012, None, false);
    tests.insert("valid_tx".into(), json!(verify_tx(&p, &ledger, &pk_a, &tx, None).is_ok()));
    let over = create_tx(&p, &banks[0], &ledger[&0], &ledger[&1].pk, &pk_a, 1, start_bal + 1, Some(0), false);
    tests.insert("overspend_false_claim".into(), json!(format!("{:?}", verify_tx(&p, &ledger, &pk_a, &over, None).err())));
    let over2 = create_tx(&p, &banks[0], &ledger[&0], &ledger[&1].pk, &pk_a, 1, start_bal + 1, Some(start_bal.wrapping_sub(start_bal + 1)), false);
    tests.insert("overspend_wrapped_claim".into(), json!(format!("{:?}", verify_tx(&p, &ledger, &pk_a, &over2, None).err())));
    let bad = create_tx(&p, &banks[0], &ledger[&0], &ledger[&1].pk, &pk_a, 1, 5_000, None, true);
    tests.insert("inconsistent_auditor_handle".into(), json!(format!("{:?}", verify_tx(&p, &ledger, &pk_a, &bad, None).err())));
    let mut tam = tx.clone(); tam.c[0] = tam.c[0] + p.g();
    tests.insert("tampered_commitment".into(), json!(format!("{:?}", verify_tx(&p, &ledger, &pk_a, &tam, None).err())));
    let mut forged = tx.clone(); forged.sig = banks[2].sig.sign(b"x");
    tests.insert("forged_signature".into(), json!(format!("{:?}", verify_tx(&p, &ledger, &pk_a, &forged, None).err())));
    // apply and test replay, receiver decryption, rollover and disclosure
    apply_tx(&mut ledger, &tx); banks[0].balance -= 123_456_789_012; banks[0].nonce += 1;
    tests.insert("replay".into(), json!(format!("{:?}", verify_tx(&p, &ledger, &pk_a, &tx, None).err())));
    tests.insert("receiver_decrypt_ok".into(), json!(decrypt_amount(&p, &bsgs, &tx, R, &banks[1].enc.sk) == Some(123_456_789_012)));
    let shares: Vec<Share> = (0..3).map(|i| partial_decrypt(&p, &committee, i, &tx, 7)).collect();
    tests.insert("threshold_disclosure_ok".into(), json!(combine_disclose(&p, &bsgs, &committee, &tx, 7, &shares) == Ok(123_456_789_012)));
    tests.insert("disclosure_below_threshold".into(), json!(format!("{:?}", combine_disclose(&p, &bsgs, &committee, &tx, 7, &shares[..2]).err())));
    tests.insert("disclosure_share_wrong_request".into(), json!(format!("{:?}", combine_disclose(&p, &bsgs, &committee, &tx, 8, &shares).err())));
    // second transfer from the same sender after the first is applied (balance tracking)
    let tx2 = create_tx(&p, &banks[0], &ledger[&0], &ledger[&2].pk, &pk_a, 2, 42, None, false);
    tests.insert("sequential_tx_after_debit".into(), json!(verify_tx(&p, &ledger, &pk_a, &tx2, None).is_ok()));
    // receiver spends after rollover of the pending credit
    rollover(&mut ledger, 1); banks[1].balance += 123_456_789_012;
    let tx3 = create_tx(&p, &banks[1], &ledger[&1], &ledger[&3].pk, &pk_a, 3, start_bal + 1_000, None, false);
    tests.insert("spend_received_funds_after_rollover".into(), json!(verify_tx(&p, &ledger, &pk_a, &tx3, None).is_ok()));
    println!("tests: {}", serde_json::Value::Object(tests.clone()));

    // ---------------- micro-benchmarks ----------------
    let (mut create, mut verify, mut apply, mut dec, mut part, mut comb3, mut sizes) = (vec![], vec![], vec![], vec![], vec![], vec![], vec![]);
    let mut tm = VerifyTiming::default();
    let mut txs = vec![];
    for i in 0..iters {
        let (sidx, ridx) = (i % 4, (i + 1 + i / 4 % 3) % 4);
        let ridx = if ridx == sidx { (sidx + 1) % 4 } else { ridx };
        let amt = rand_amount(&mut rng).min(banks[sidx].balance);
        let pk_r = ledger[&(ridx as u32)].pk;
        let a = Instant::now();
        let tx = create_tx(&p, &banks[sidx], &ledger[&(sidx as u32)], &pk_r, &pk_a, ridx as u32, amt, None, false);
        create.push(a.elapsed().as_secs_f64() * 1e3);
        let a = Instant::now();
        verify_tx(&p, &ledger, &pk_a, &tx, Some(&mut tm)).expect("verify");
        verify.push(a.elapsed().as_secs_f64() * 1e3);
        let a = Instant::now(); apply_tx(&mut ledger, &tx); apply.push(a.elapsed().as_secs_f64() * 1e3);
        banks[sidx].balance -= amt; banks[sidx].nonce += 1;
        let a = Instant::now(); let v = decrypt_amount(&p, &bsgs, &tx, R, &banks[ridx].enc.sk); dec.push(a.elapsed().as_secs_f64() * 1e3);
        assert_eq!(v, Some(amt));
        rollover(&mut ledger, ridx as u32); banks[ridx].balance += amt;
        let a = Instant::now(); let sh: Vec<Share> = (0..3).map(|k| partial_decrypt(&p, &committee, k, &tx, i as u64)).collect();
        part.push(a.elapsed().as_secs_f64() * 1e3 / 3.0);
        let a = Instant::now(); assert_eq!(combine_disclose(&p, &bsgs, &committee, &tx, i as u64, &sh), Ok(amt)); comb3.push(a.elapsed().as_secs_f64() * 1e3);
        sizes.push(tx.size_bytes() as f64);
        txs.push(tx);
    }
    let n = iters as f64;
    // disclosure cost versus committee threshold
    let mut thr = vec![];
    for (nn, t) in [(1usize, 1usize), (3, 2), (5, 3), (7, 4), (9, 5)] {
        let c = committee_setup(&p, nn, t);
        let s = Bank::new(&p, 99, 1 << 40); let st = genesis(&p, &s);
        let mut l2 = ledger.clone(); l2.insert(99, st.clone());
        let tx = create_tx(&p, &s, &st, &ledger[&1].pk, &c.pk_a, 1, 987_654_321, None, false);
        let mut v = vec![];
        for _ in 0..20 { let a = Instant::now(); let sh: Vec<Share> = (0..t).map(|k| partial_decrypt(&p, &c, k, &tx, 1)).collect();
            assert_eq!(combine_disclose(&p, &bsgs, &c, &tx, 1, &sh), Ok(987_654_321)); v.push(a.elapsed().as_secs_f64() * 1e3); }
        thr.push(json!({"n": nn, "t": t, "ms": stats(&v)}));
    }
    // plaintext baseline: Ed25519 signature over a 64-byte plaintext transaction
    let sk = SigningKey::generate(&mut OsRng); let vk = sk.verifying_key(); let msg = [7u8; 64];
    let (mut bs, mut bv) = (vec![], vec![]);
    for _ in 0..1000 { let a = Instant::now(); let s = sk.sign(&msg); bs.push(a.elapsed().as_secs_f64() * 1e3);
        let a = Instant::now(); vk.verify(&msg, &s).unwrap(); bv.push(a.elapsed().as_secs_f64() * 1e3); }
    // parallel verification throughput on all cores (independent transactions, frozen ledger snapshot)
    let mut par = vec![];
    let snap = { let mut l = HashMap::new(); for b in &banks { l.insert(b.id, genesis(&p, b)); } l };
    let probe: Vec<Tx> = (0..256).map(|i| { let s = &banks[i % 4]; let r = (i + 1) % 4;
        create_tx(&p, s, &snap[&s.id], &snap[&(r as u32)].pk, &pk_a, r as u32, 1000 + i as u64, None, false) }).collect();
    let cores = std::thread::available_parallelism().map(|x| x.get()).unwrap_or(1);
    for th in [1usize, cores] {
        let a = Instant::now();
        std::thread::scope(|sc| { for k in 0..th { let (p, snap, probe, pk_a) = (&p, &snap, &probe, &pk_a);
            sc.spawn(move || { for (i, tx) in probe.iter().enumerate() { if i % th == k { verify_tx(p, snap, pk_a, tx, None).unwrap(); } } }); } });
        par.push(json!({"threads": th, "tx_per_s": probe.len() as f64 / a.elapsed().as_secs_f64()}));
    }
    let rp_len = txs[0].rp.to_bytes().len();
    let res = json!({
        "iters": iters, "cores": cores, "bsgs_build_s": bsgs_build_s, "tests": tests,
        "create_ms": stats(&create), "verify_ms": stats(&verify), "apply_ms": stats(&apply),
        "receiver_decrypt_ms": stats(&dec), "partial_decrypt_ms": stats(&part), "combine_3of5_ms": stats(&comb3),
        "verify_breakdown_ms": {"signature": tm.sig_us / n / 1e3, "validity": tm.valid_us / n / 1e3, "balance": tm.bal_us / n / 1e3, "range": tm.range_us / n / 1e3},
        "tx_bytes": stats(&sizes), "range_proof_bytes": rp_len,
        "baseline_ed25519": {"sign_ms": stats(&bs), "verify_ms": stats(&bv), "tx_bytes": 8 + 8 + 8 + 4 + 4 + 64},
        "disclosure_by_threshold": thr, "parallel_verify": par,
    });
    std::fs::write(&out, serde_json::to_string_pretty(&res).unwrap()).unwrap();
    println!("{}", serde_json::to_string_pretty(&res).unwrap());
}
