//! PPTV-RA cryptographic layer.
//! Group: Ristretto255. G = Pedersen value base, H = Pedersen blinding base.
//! Account key: pk = sk * H. Twisted ElGamal ciphertext of value v under pk with randomness r:
//!   (C, D) = (v*G + r*H, r*pk)   decrypt: v*G = C - sk^{-1} * D
//! A transfer amount A < 2^64 is split into 32-bit limbs (lo, hi) so receivers and the
//! auditor can recover each limb with a baby-step giant-step search.

use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek_ng::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek_ng::scalar::Scalar;
use curve25519_dalek_ng::traits::{Identity, MultiscalarMul};
use merlin::Transcript;
use rand::rngs::OsRng;
use std::collections::HashMap;

pub const LIMB: u64 = 1u64 << 32;

pub struct Params {
    pub pc: PedersenGens,
    pub bp: BulletproofGens,
}
impl Params {
    pub fn new() -> Self { Params { pc: PedersenGens::default(), bp: BulletproofGens::new(32, 4) } }
    pub fn g(&self) -> RistrettoPoint { self.pc.B }
    pub fn h(&self) -> RistrettoPoint { self.pc.B_blinding }
}

#[derive(Clone)]
pub struct KeyPair { pub sk: Scalar, pub pk: RistrettoPoint }
impl KeyPair {
    pub fn new(p: &Params) -> Self { let sk = Scalar::random(&mut OsRng); KeyPair { sk, pk: sk * p.h() } }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Ct { pub c: RistrettoPoint, pub d: RistrettoPoint }
impl Ct {
    pub fn zero() -> Self { Ct { c: RistrettoPoint::identity(), d: RistrettoPoint::identity() } }
    pub fn add(&self, o: &Ct) -> Ct { Ct { c: self.c + o.c, d: self.d + o.d } }
    pub fn sub(&self, o: &Ct) -> Ct { Ct { c: self.c - o.c, d: self.d - o.d } }
}

fn challenge(t: &mut Transcript, label: &'static [u8]) -> Scalar {
    let mut b = [0u8; 64]; t.challenge_bytes(label, &mut b); Scalar::from_bytes_mod_order_wide(&b)
}
fn ap(t: &mut Transcript, label: &'static [u8], p: &RistrettoPoint) { t.append_message(label, p.compress().as_bytes()); }

/// Ciphertext-validity proof for one limb: knowledge of (a, r) with
/// C = aG + rH and D_j = r*pk_j for every handle j (sender, receiver, auditor).
#[derive(Clone)]
pub struct ValidityProof { pub tc: RistrettoPoint, pub tj: Vec<RistrettoPoint>, pub za: Scalar, pub zr: Scalar }

pub fn prove_validity(p: &Params, t: &mut Transcript, a: u64, r: &Scalar, c: &RistrettoPoint, pks: &[RistrettoPoint], ds: &[RistrettoPoint]) -> ValidityProof {
    let (ka, kr) = (Scalar::random(&mut OsRng), Scalar::random(&mut OsRng));
    let tc = ka * p.g() + kr * p.h();
    let tj: Vec<_> = pks.iter().map(|pk| kr * pk).collect();
    ap(t, b"C", c); for d in ds { ap(t, b"D", d); } ap(t, b"TC", &tc); for x in &tj { ap(t, b"TJ", x); }
    let e = challenge(t, b"e-valid");
    ValidityProof { tc, tj, za: ka + e * Scalar::from(a), zr: kr + e * r }
}
pub fn verify_validity(p: &Params, t: &mut Transcript, pr: &ValidityProof, c: &RistrettoPoint, pks: &[RistrettoPoint], ds: &[RistrettoPoint]) -> bool {
    ap(t, b"C", c); for d in ds { ap(t, b"D", d); } ap(t, b"TC", &pr.tc); for x in &pr.tj { ap(t, b"TJ", x); }
    let e = challenge(t, b"e-valid");
    if pr.za * p.g() + pr.zr * p.h() != pr.tc + e * c { return false; }
    pks.iter().zip(ds).zip(&pr.tj).all(|((pk, d), tj)| pr.zr * pk == tj + e * d)
}

/// Balance-equality proof: the sender's post-transfer balance ciphertext (BC, BD) encrypts
/// b = b_lo + 2^32 b_hi under pk_S, and fresh commitments Ĉ_lo, Ĉ_hi open to (b_lo, b_hi).
/// Witness: u = sk_S^{-1}, b_lo, b_hi, ρ_lo, ρ_hi.
///   BC = b_lo G + 2^32 b_hi G + u BD,   H = u pk_S,   Ĉ_k = b_k G + ρ_k H
#[derive(Clone)]
pub struct BalanceProof { pub t1: RistrettoPoint, pub t2: RistrettoPoint, pub t3: RistrettoPoint, pub t4: RistrettoPoint, pub z: [Scalar; 5] }

pub fn prove_balance(p: &Params, t: &mut Transcript, sk: &Scalar, pk: &RistrettoPoint, bal: &Ct, b: u64, rho: &[Scalar; 2], ch: &[RistrettoPoint; 2]) -> BalanceProof {
    let u = sk.invert();
    let (bl, bh) = (Scalar::from(b % LIMB), Scalar::from(b / LIMB));
    let two32 = Scalar::from(LIMB);
    let k: Vec<Scalar> = (0..5).map(|_| Scalar::random(&mut OsRng)).collect();
    let t1 = k[1] * p.g() + (two32 * k[2]) * p.g() + k[0] * bal.d;
    let t2 = k[0] * pk;
    let t3 = k[1] * p.g() + k[3] * p.h();
    let t4 = k[2] * p.g() + k[4] * p.h();
    ap(t, b"BC", &bal.c); ap(t, b"BD", &bal.d); ap(t, b"PK", pk); ap(t, b"CH0", &ch[0]); ap(t, b"CH1", &ch[1]);
    for x in [&t1, &t2, &t3, &t4] { ap(t, b"T", x); }
    let e = challenge(t, b"e-bal");
    let w = [u, bl, bh, rho[0], rho[1]];
    let mut z = [Scalar::zero(); 5];
    for i in 0..5 { z[i] = k[i] + e * w[i]; }
    BalanceProof { t1, t2, t3, t4, z }
}
pub fn verify_balance(p: &Params, t: &mut Transcript, pr: &BalanceProof, pk: &RistrettoPoint, bal: &Ct, ch: &[RistrettoPoint; 2]) -> bool {
    ap(t, b"BC", &bal.c); ap(t, b"BD", &bal.d); ap(t, b"PK", pk); ap(t, b"CH0", &ch[0]); ap(t, b"CH1", &ch[1]);
    for x in [&pr.t1, &pr.t2, &pr.t3, &pr.t4] { ap(t, b"T", x); }
    let e = challenge(t, b"e-bal");
    let two32 = Scalar::from(LIMB); let z = &pr.z;
    z[1] * p.g() + (two32 * z[2]) * p.g() + z[0] * bal.d == pr.t1 + e * bal.c
        && z[0] * pk == pr.t2 + e * p.h()
        && z[1] * p.g() + z[3] * p.h() == pr.t3 + e * ch[0]
        && z[2] * p.g() + z[4] * p.h() == pr.t4 + e * ch[1]
}

/// Chaum-Pedersen DLEQ: log_H(W) = log_D(S). Used by regulator nodes for partial decryptions.
#[derive(Clone)]
pub struct Dleq { pub a1: RistrettoPoint, pub a2: RistrettoPoint, pub z: Scalar }
pub fn prove_dleq(t: &mut Transcript, w: &Scalar, h: &RistrettoPoint, wp: &RistrettoPoint, d: &RistrettoPoint, s: &RistrettoPoint) -> Dleq {
    let k = Scalar::random(&mut OsRng); let (a1, a2) = (k * h, k * d);
    for x in [wp, d, s, &a1, &a2] { ap(t, b"X", x); }
    let e = challenge(t, b"e-dleq"); Dleq { a1, a2, z: k + e * w }
}
pub fn verify_dleq(t: &mut Transcript, pr: &Dleq, h: &RistrettoPoint, wp: &RistrettoPoint, d: &RistrettoPoint, s: &RistrettoPoint) -> bool {
    for x in [wp, d, s, &pr.a1, &pr.a2] { ap(t, b"X", x); }
    let e = challenge(t, b"e-dleq");
    pr.z * h == pr.a1 + e * wp && pr.z * d == pr.a2 + e * s
}

/// Baby-step giant-step table for 32-bit discrete logs base G.
pub struct Bsgs { table: HashMap<[u8; 32], u32>, giant: RistrettoPoint, baby_bits: u32 }
impl Bsgs {
    pub fn new(p: &Params, baby_bits: u32) -> Self {
        let mut table = HashMap::with_capacity(1 << baby_bits);
        let mut acc = RistrettoPoint::identity();
        for j in 0..(1u32 << baby_bits) { table.insert(acc.compress().to_bytes(), j); acc += p.g(); }
        Bsgs { table, giant: Scalar::from(1u64 << baby_bits) * p.g(), baby_bits }
    }
    pub fn solve(&self, target: &RistrettoPoint) -> Option<u32> {
        let mut cur = *target;
        for i in 0..(1u32 << (32 - self.baby_bits)) {
            if let Some(j) = self.table.get(&cur.compress().to_bytes()) { return Some((i << self.baby_bits) + j); }
            cur -= self.giant;
        }
        None
    }
}

/// Limb split helper.
pub fn limbs(a: u64) -> [u64; 2] { [a % LIMB, a / LIMB] }
pub fn combine(lo: &RistrettoPoint, hi: &RistrettoPoint) -> RistrettoPoint { lo + Scalar::from(LIMB) * hi }

/// Aggregated 32-bit range proof over four values.
pub fn prove_range(p: &Params, t: &mut Transcript, v: &[u64; 4], r: &[Scalar; 4]) -> (RangeProof, Vec<CompressedRistretto>) {
    RangeProof::prove_multiple(&p.bp, &p.pc, t, &v[..], &r[..], 32).expect("range proof")
}
pub fn verify_range(p: &Params, t: &mut Transcript, pr: &RangeProof, cs: &[CompressedRistretto; 4]) -> bool {
    pr.verify_multiple(&p.bp, &p.pc, t, &cs[..], 32).is_ok()
}

pub fn msm(s: &[Scalar], pts: &[RistrettoPoint]) -> RistrettoPoint { RistrettoPoint::multiscalar_mul(s, pts) }
