//! PPTV-RA transaction protocol: creation (Alg. 1), validation (Alg. 2), state update,
//! receiver decryption and t-of-n logged regulatory disclosure (Alg. 4).
use crate::crypto::*;
use bulletproofs::RangeProof;
use curve25519_dalek_ng::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek_ng::scalar::Scalar;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use merlin::Transcript;
use rand::rngs::OsRng;
use sha2::{Digest, Sha512};
use std::collections::HashMap;

pub const S: usize = 0; pub const R: usize = 1; pub const A: usize = 2;

pub struct Bank { pub id: u32, pub enc: KeyPair, pub sig: SigningKey, pub balance: u64, pub nonce: u64 }
impl Bank {
    pub fn new(p: &Params, id: u32, balance: u64) -> Self {
        Bank { id, enc: KeyPair::new(p), sig: SigningKey::generate(&mut OsRng), balance, nonce: 0 }
    }
}

#[derive(Clone)]
pub struct AccountState { pub pk: RistrettoPoint, pub vk: VerifyingKey, pub avail: Ct, pub pending: Ct, pub nonce: u64 }

#[derive(Clone)]
pub struct Tx {
    pub from: u32, pub to: u32, pub nonce: u64,
    pub c: [RistrettoPoint; 2],          // limb commitments
    pub d: [[RistrettoPoint; 2]; 3],     // decryption handles [role][limb]
    pub vp: [ValidityProof; 2],
    pub ch: [RistrettoPoint; 2],         // fresh commitments to remaining balance limbs
    pub bp: BalanceProof,
    pub rp: RangeProof,
    pub sig: Signature,
}

impl Tx {
    pub fn size_bytes(&self) -> usize {
        let pts = 2 + 6 + 2 * (1 + 3) + 2 + 4; let scalars = 2 * 2 + 5;
        4 + 4 + 8 + 32 * (pts + scalars) + self.rp.to_bytes().len() + 64
    }
    pub fn amount_ct(&self, role: usize) -> Ct { Ct { c: combine(&self.c[0], &self.c[1]), d: combine(&self.d[role][0], &self.d[role][1]) } }
    fn body_hash(&self) -> [u8; 64] {
        let mut h = Sha512::new();
        h.update(self.from.to_le_bytes()); h.update(self.to.to_le_bytes()); h.update(self.nonce.to_le_bytes());
        for x in self.c.iter().chain(self.d.iter().flatten()).chain(self.ch.iter()) { h.update(x.compress().as_bytes()); }
        for v in &self.vp { h.update(v.tc.compress().as_bytes()); for t in &v.tj { h.update(t.compress().as_bytes()); } h.update(v.za.as_bytes()); h.update(v.zr.as_bytes()); }
        for t in [&self.bp.t1, &self.bp.t2, &self.bp.t3, &self.bp.t4] { h.update(t.compress().as_bytes()); }
        for z in &self.bp.z { h.update(z.as_bytes()); }
        h.update(self.rp.to_bytes());
        h.finalize().into()
    }
}

fn tx_transcript(from: u32, to: u32, nonce: u64) -> Transcript {
    let mut t = Transcript::new(b"PPTV-RA/tx/v1");
    t.append_u64(b"from", from as u64); t.append_u64(b"to", to as u64); t.append_u64(b"nonce", nonce); t
}

/// Algorithm 1: sender-side construction. `claim` lets tests forge a false remaining balance.
pub fn create_tx(p: &Params, s: &Bank, st_s: &AccountState, pk_r: &RistrettoPoint, pk_a: &RistrettoPoint, to: u32, amount: u64, claim: Option<u64>, bad_aud: bool) -> Tx {
    let a = limbs(amount);
    let r = [Scalar::random(&mut OsRng), Scalar::random(&mut OsRng)];
    let c = [Scalar::from(a[0]) * p.g() + r[0] * p.h(), Scalar::from(a[1]) * p.g() + r[1] * p.h()];
    let pks = [st_s.pk, *pk_r, *pk_a];
    let mut d = [[RistrettoPoint::default(); 2]; 3];
    for j in 0..3 { for l in 0..2 { d[j][l] = r[l] * pks[j]; } }
    if bad_aud { d[A][0] = Scalar::random(&mut OsRng) * pk_a; }
    let nonce = st_s.nonce + 1;
    let mut t = tx_transcript(s.id, to, nonce);
    let vp = [0, 1].map(|l| prove_validity(p, &mut t, a[l], &r[l], &c[l], &pks, &[d[0][l], d[1][l], d[2][l]]));
    // remaining balance ciphertext after debit
    let amt = Ct { c: combine(&c[0], &c[1]), d: combine(&d[S][0], &d[S][1]) };
    let new_bal = st_s.avail.sub(&amt);
    let b = claim.unwrap_or(s.balance.wrapping_sub(amount));
    let bl = limbs(b);
    let rho = [Scalar::random(&mut OsRng), Scalar::random(&mut OsRng)];
    let ch = [Scalar::from(bl[0]) * p.g() + rho[0] * p.h(), Scalar::from(bl[1]) * p.g() + rho[1] * p.h()];
    let bp = prove_balance(p, &mut t, &s.enc.sk, &st_s.pk, &new_bal, b, &rho, &ch);
    let (rp, _) = prove_range(p, &mut t, &[a[0], a[1], bl[0], bl[1]], &[r[0], r[1], rho[0], rho[1]]);
    let mut tx = Tx { from: s.id, to, nonce, c, d, vp, ch, bp, rp, sig: Signature::from_bytes(&[0u8; 64]) };
    tx.sig = s.sig.sign(&tx.body_hash());
    tx
}

#[derive(Default, Clone, Copy, Debug)]
pub struct VerifyTiming { pub sig_us: f64, pub valid_us: f64, pub bal_us: f64, pub range_us: f64 }

/// Algorithm 2: validator-side check. Returns Ok(()) or the failed predicate.
pub fn verify_tx(p: &Params, ledger: &HashMap<u32, AccountState>, pk_a: &RistrettoPoint, tx: &Tx, tm: Option<&mut VerifyTiming>) -> Result<(), &'static str> {
    use std::time::Instant;
    let st_s = ledger.get(&tx.from).ok_or("unknown sender")?;
    let st_r = ledger.get(&tx.to).ok_or("unknown receiver")?;
    if tx.nonce != st_s.nonce + 1 { return Err("nonce"); }
    let t0 = Instant::now();
    st_s.vk.verify(&tx.body_hash(), &tx.sig).map_err(|_| "signature")?;
    let t1 = Instant::now();
    let pks = [st_s.pk, st_r.pk, *pk_a];
    let mut t = tx_transcript(tx.from, tx.to, tx.nonce);
    for l in 0..2 {
        if !verify_validity(p, &mut t, &tx.vp[l], &tx.c[l], &pks, &[tx.d[0][l], tx.d[1][l], tx.d[2][l]]) { return Err("validity"); }
    }
    let t2 = Instant::now();
    let new_bal = st_s.avail.sub(&tx.amount_ct(S));
    if !verify_balance(p, &mut t, &tx.bp, &st_s.pk, &new_bal, &tx.ch) { return Err("balance"); }
    let t3 = Instant::now();
    let cs: [CompressedRistretto; 4] = [tx.c[0].compress(), tx.c[1].compress(), tx.ch[0].compress(), tx.ch[1].compress()];
    if !verify_range(p, &mut t, &tx.rp, &cs) { return Err("range"); }
    let t4 = Instant::now();
    if let Some(m) = tm {
        m.sig_us += (t1 - t0).as_secs_f64() * 1e6; m.valid_us += (t2 - t1).as_secs_f64() * 1e6;
        m.bal_us += (t3 - t2).as_secs_f64() * 1e6; m.range_us += (t4 - t3).as_secs_f64() * 1e6;
    }
    Ok(())
}

/// Homomorphic state update after commit: debit sender's available balance, credit receiver's pending.
pub fn apply_tx(ledger: &mut HashMap<u32, AccountState>, tx: &Tx) {
    let amt_s = tx.amount_ct(S); let amt_r = tx.amount_ct(R);
    let s = ledger.get_mut(&tx.from).unwrap(); s.avail = s.avail.sub(&amt_s); s.nonce = tx.nonce;
    let r = ledger.get_mut(&tx.to).unwrap(); r.pending = r.pending.add(&amt_r);
}
/// Owner-signed rollover of pending credits into the available balance (prevents front-running of proofs).
pub fn rollover(ledger: &mut HashMap<u32, AccountState>, id: u32) {
    let s = ledger.get_mut(&id).unwrap(); s.avail = s.avail.add(&s.pending); s.pending = Ct::zero();
}

/// Decrypt one transferred amount with a role key (receiver or single-key auditor).
pub fn decrypt_amount(_p: &Params, bsgs: &Bsgs, tx: &Tx, role: usize, sk: &Scalar) -> Option<u64> {
    let u = sk.invert();
    let mut out = 0u64;
    for l in 0..2 {
        let vg = tx.c[l] - u * tx.d[role][l];
        out += (bsgs.solve(&vg)? as u64) << (32 * l);
    }
    Some(out)
}

// ---------------- t-of-n regulator committee ----------------
pub struct Committee { pub pk_a: RistrettoPoint, pub shares: Vec<(u64, Scalar)>, pub vks: Vec<RistrettoPoint>, pub t: usize }
/// Dealer setup: w = sk_A^{-1} is Shamir-shared; pk_A = w^{-1} H; verification keys W_i = w_i H.
pub fn committee_setup(p: &Params, n: usize, t: usize) -> Committee {
    let coeffs: Vec<Scalar> = (0..t).map(|_| Scalar::random(&mut OsRng)).collect();
    let w = coeffs[0];
    let shares: Vec<(u64, Scalar)> = (1..=n as u64).map(|i| {
        let x = Scalar::from(i); let mut acc = Scalar::zero(); let mut xp = Scalar::one();
        for c in &coeffs { acc += c * xp; xp *= x; } (i, acc) }).collect();
    let vks = shares.iter().map(|(_, s)| s * p.h()).collect();
    Committee { pk_a: w.invert() * p.h(), shares, vks, t }
}
pub struct Share { pub idx: u64, pub s: [RistrettoPoint; 2], pub pr: [Dleq; 2] }
/// Released by node i only after the audit contract has logged request `req_id`.
pub fn partial_decrypt(p: &Params, c: &Committee, i: usize, tx: &Tx, req_id: u64) -> Share {
    let (idx, wi) = c.shares[i];
    let s = [wi * tx.d[A][0], wi * tx.d[A][1]];
    let pr = [0, 1].map(|l| { let mut t = Transcript::new(b"PPTV-RA/disclose"); t.append_u64(b"req", req_id);
        prove_dleq(&mut t, &wi, &p.h(), &c.vks[i], &tx.d[A][l], &s[l]) });
    Share { idx, s, pr }
}
pub fn combine_disclose(p: &Params, bsgs: &Bsgs, c: &Committee, tx: &Tx, req_id: u64, shares: &[Share]) -> Result<u64, &'static str> {
    if shares.len() < c.t { return Err("below threshold"); }
    let sel = &shares[..c.t];
    for sh in sel { for l in 0..2 { let mut t = Transcript::new(b"PPTV-RA/disclose"); t.append_u64(b"req", req_id);
        if !verify_dleq(&mut t, &sh.pr[l], &p.h(), &c.vks[(sh.idx - 1) as usize], &tx.d[A][l], &sh.s[l]) { return Err("bad share"); } } }
    let xs: Vec<Scalar> = sel.iter().map(|s| Scalar::from(s.idx)).collect();
    let lam: Vec<Scalar> = (0..xs.len()).map(|i| { let mut num = Scalar::one(); let mut den = Scalar::one();
        for j in 0..xs.len() { if i != j { num *= xs[j]; den *= xs[j] - xs[i]; } } num * den.invert() }).collect();
    let mut out = 0u64;
    for l in 0..2 {
        let rh = msm(&lam, &sel.iter().map(|s| s.s[l]).collect::<Vec<_>>());
        let v = bsgs.solve(&(tx.c[l] - rh)).ok_or("dlog")?;
        out += (v as u64) << (32 * l);
    }
    Ok(out)
}
