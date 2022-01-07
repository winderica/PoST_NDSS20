use std::time::Instant;

use openssl::{
    bn::{BigNum, BigNumContext},
    hash::{DigestBytes, Hasher, MessageDigest},
    rand::rand_bytes,
};

fn sha3(data: &[u8]) -> DigestBytes {
    let mut h = Hasher::new(MessageDigest::sha3_256()).unwrap();
    h.update(data).unwrap();
    h.finish().unwrap()
}

// Unlike SHA-1 and SHA-2, Keccak does not have the length-extension weakness, hence does not need the HMAC nested construction. Instead, MAC computation can be performed by simply prepending the message with the key.
fn hmac(key: &[u8], data: &[u8]) -> DigestBytes {
    let mut h = Hasher::new(MessageDigest::sha3_256()).unwrap();
    h.update(key).unwrap();
    h.update(data).unwrap();
    h.finish().unwrap()
}

fn setup(n_bits: i32) -> (BigNum, BigNum) {
    let mut p = BigNum::new().unwrap();
    p.generate_prime(n_bits >> 1, false, None, None).unwrap();
    let mut q = BigNum::new().unwrap();
    q.generate_prime(n_bits >> 1, false, None, None).unwrap();
    (p, q)
}

fn eval_trap(x: &[u8], n: &BigNum, e: &BigNum, ctx: &mut BigNumContext) -> Vec<u8> {
    let mut r = BigNum::new().unwrap();
    r.mod_exp(&BigNum::from_slice(x).unwrap(), &e, n, ctx)
        .unwrap();
    r.to_vec()
}

fn eval(x: &[u8], n: &BigNum, t: usize) -> Vec<u8> {
    let mut g = BigNum::from_slice(x).unwrap();
    for _ in 0..(1 << t) {
        g = &(&g * &g) % n;
    }
    g.to_vec()
}

fn store(c: &[u8], d: &[u8], p: &BigNum, q: &BigNum, t: i32, k: i32) -> (Vec<u8>, Vec<u8>) {
    let mut ctx = BigNumContext::new().unwrap();
    let one = BigNum::from_u32(1).unwrap();

    let n = p * q;
    let phi = &(p - &one) * &(q - &one);
    let mut e = BigNum::new().unwrap();
    e.set_bit(1 << t).unwrap();
    e = &e % &phi;

    let mut c = c.to_vec();
    let mut cs = vec![];
    let mut vs = vec![];
    for _ in 0..=k {
        let v = hmac(&c, d);
        cs.extend_from_slice(&c);
        vs.extend_from_slice(&v);
        c = sha3(&eval_trap(&sha3(&v), &n, &e, &mut ctx)).to_vec();
    }
    (sha3(&cs).to_vec(), sha3(&vs).to_vec())
}

fn prove(c: &[u8], d: &[u8], n: &BigNum, t: usize, k: i32) -> (Vec<u8>, Vec<u8>) {
    let mut c = c.to_vec();
    let mut cs = vec![];
    let mut vs = vec![];
    for _ in 0..=k {
        let v = hmac(&c, d);
        cs.extend_from_slice(&c);
        vs.extend_from_slice(&v);
        c = sha3(&eval(&sha3(&v), n, t)).to_vec();
    }
    (sha3(&cs).to_vec(), sha3(&vs).to_vec())
}

fn main() {
    const T: usize = 28;
    const N_BITS: i32 = 2048;

    for k in 1..5 {
        for size in [64, 128, 192, 256] {
            println!("{} month(s), {} MB", k, size);

            let mut c = [0; 32];
            rand_bytes(&mut c).unwrap();

            let file = vec![0; size * 1024 * 1024];

            let (p, q) = setup(N_BITS);

            let now = Instant::now();
            let a = store(&c, &file, &p, &q, T as i32, k * 720);
            println!("store: {:.3?}", now.elapsed());

            let now = Instant::now();
            let b = prove(&c, &file, &(&p * &q), T, k * 720);
            println!("prove: {:.3?}", now.elapsed());

            assert_eq!(a, b);
        }
    }
}
