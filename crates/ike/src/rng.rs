//! Small randomness helpers (OS CSPRNG via `getrandom`) for SPIs, nonces, DH
//! private keys, and SK IVs.

/// Fill `buf` with cryptographically secure random bytes.
pub fn fill(buf: &mut [u8]) {
    getrandom::getrandom(buf).expect("OS CSPRNG unavailable");
}

/// A fresh, non-zero 8-byte IKE SPI.
pub fn spi() -> [u8; 8] {
    loop {
        let mut s = [0u8; 8];
        fill(&mut s);
        if s != [0u8; 8] {
            return s;
        }
    }
}

/// A fresh nonce of `len` bytes (RFC 7296 requires 16..=256).
pub fn nonce(len: usize) -> Vec<u8> {
    let mut n = vec![0u8; len];
    fill(&mut n);
    n
}
