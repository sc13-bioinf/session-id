 
use digest::{InvalidLength,core_api::{BlockSizeUser},Output};
use sha2::{Sha256,Digest};

const IPAD: u8 = 0x36;
const OPAD: u8 = 0x5C;

fn get_der_key<D: Digest + BlockSizeUser>(key: &[u8]) -> [u8;8]
{
    let mut der_key: [u8;8] = [0;8];
    // The key that HMAC processes must be the same as the block size of the
    // underlying hash function. If the provided key is smaller than that,
    // we just pad it with zeros. If its larger, we hash it and then pad it
    // with zeros.
    if key.len () <= der_key.len () {
        der_key[..key.len ()].copy_from_slice (key);
    } else {
        let hash = D::digest (key);
        // All commonly used hash functions have block size bigger
        // than output hash size, but to be extra rigorous we
        // handle the potential uncommon cases as well.
        // The condition is calcualted at compile time, so this
        // branch gets removed from the final binary.
        if hash.len () <= der_key.len () {
            der_key[..hash.len ()].copy_from_slice (&hash);
        } else {
            let n = der_key.len ();
            der_key.copy_from_slice (&hash[..n]);
        }
    }
    der_key
}

#[derive(Clone)]
pub struct SimpleHmac {
    digest: Sha256,
    opad_key: [u8;8],
    #[cfg(feature = "reset")]
    ipad_key: [u8;8],
}

impl SimpleHmac
{
    #[inline]
    pub fn new_from_slice (key: &[u8])
        -> Result<Self, InvalidLength>
    {
        let der_key = get_der_key::<Sha256> (key);
        let mut ipad_key = der_key.clone ();
        for b in ipad_key.iter_mut ()
        {
            *b ^= IPAD;
        }
        let mut digest = Sha256::new ();
        digest.update (&ipad_key);

        let mut opad_key = der_key;
        for b in opad_key.iter_mut ()
        {
            *b ^= OPAD;
        }

        Ok(Self {
            digest,
            opad_key,
            #[cfg(feature = "reset")]
            ipad_key,
        })
    }

    #[inline]
    pub fn finalize_into (self, out: &mut Output<Sha256>)
    {
        let mut h = Sha256::new ();
        h.update (&self.opad_key);
        h.update (&self.digest.finalize ());
        h.finalize_into (out);
    }

    #[inline]
    pub fn finalize_fixed (self)
        -> Output<Sha256>
    {
        let mut out = Default::default ();
        self.finalize_into (&mut out);
        out
    }

    pub fn update (&mut self, data: &[u8])
    {
        self.digest.update (data);
    }
}

