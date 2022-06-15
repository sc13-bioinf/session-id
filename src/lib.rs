
use log::debug;
use rand::{thread_rng, Rng};
use rayon::prelude::*;

mod hmac;

pub struct State {
    secret: Vec<u8>,
    salt: Vec<u8>,
    step: usize,
    rounds: usize,
}


pub struct SessionId {
    session: Box<State>,
}

#[inline(always)]
fn xor(res: &mut [u8], salt: &[u8]) {
    debug_assert!(salt.len() >= res.len(), "length mismatch in xor");
    res.iter_mut().zip(salt.iter()).for_each(|(a, b)| *a ^= b);
}

#[inline(always)]
fn pbkdf2_body (i: u32, chunk: &mut [u8], prf: &hmac::SimpleHmac, salt: &[u8], rounds: u32)
{
    for v in chunk.iter_mut() {
        *v = 0;
    }

    let mut salt = {
        let mut prfc = prf.clone();
        prfc.update(salt);
        prfc.update(&(i + 1).to_be_bytes());

        let salt = prfc.finalize_fixed();
        xor(chunk, &salt);
        salt
    };

    for _ in 1..rounds {
        let mut prfc = prf.clone();
        prfc.update(&salt);
        salt = prfc.finalize_fixed();

        xor(chunk, &salt);
    }
}

#[inline]
fn pbkdf2 (password: &[u8], salt: &[u8], rounds: u32, res: &mut [u8])
{
    let n = 8;
    let prf = hmac::SimpleHmac::new_from_slice (password).expect("PRF initialization failure");

    res.par_chunks_mut (n).enumerate().for_each(|(i, chunk)| {
        pbkdf2_body(i as u32, chunk, &prf, salt, rounds);
    });
}

impl SessionId {

    pub fn new(rounds: usize, salt: Vec<u8>) -> SessionId {
        let mut array = [0_u8; 32];
        thread_rng().fill(&mut array);
        let s = Box::new(State {
                secret: array.to_vec(),
                salt: salt,
                step: 0,
                rounds: rounds,
            });

        SessionId {
            session: s,
        }
    }

    pub fn get(&self) -> Vec<u8> {
        let mut v = [0_u8; 32];
        pbkdf2 (
            &self.session.secret,
            &self.session.salt,
	    (self.session.rounds + self.session.step) as u32,
            &mut v,
        );
        v.to_vec()
    }

    pub fn get_b64(&self)
        -> String
    {
        debug! ("get_b64.secret: {:x?}", self.get_secret ());
        let v = self.get();
        debug! ("get_b64.v {:x?}", &v);
        let b64 = base64::encode_config (&v, base64::URL_SAFE_NO_PAD);
        b64
    }

    pub fn next(&mut self) {
        self.session.step = self.session.step + 1;
        //&self
    }

    pub fn get_secret(&self) -> Vec<u8> {
        self.session.secret.to_vec()
    }

    pub fn get_secret_b64(&self) -> String {
        let v = self.get_secret();
        let b64 = base64::encode(&v);
        b64
    }

    pub fn set_secret(&mut self, secret: Vec<u8>) {
        self.session.secret = secret;
    }
}


#[cfg(test)]
mod tests {

    use log::info;
    use test_log::test;

    #[test]
    fn it_works() {
        let salt = hex::decode("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        let mut s = super::SessionId::new(1000, salt);

        let ss = hex::decode("cccccccccccccccccccccccccccccccc").unwrap();
        s.set_secret(ss.to_vec());

        info!("r1= {:x?}", &s.get());
        info!("r1= {:x?}", &s.get());
        s.next();
        info!("r1= {:x?}", &s.get());
        info!("r1= {:x?}", &s.get());
        s.next();
        info!("r1= {:x?}", &s.get());
        info!("r1= {}", &s.get_b64());

        assert_eq!(2 + 2, 4);
    }

    #[test]
    fn it_works_ns ()
    {
        let salt = hex::decode("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        let s = super::SessionId::new(1000, salt);

        info!("r2= {:x?}", &s.get());
        info!("r2= {:x?}", &s.get());
        info!("r2= {:x?}", &s.get());

        assert_eq!(2 + 2, 4);
    }

    #[test]
    fn it_works_short_salt ()
    {
        // Sha256 block is 512 bits == 8 * 32 (here we use only 8 * 16)
        //let salt = hex::decode("aaaaaaaaaaaaaaaa").unwrap();
        let salt = "foobar".as_bytes ().to_vec ();
        let s = super::SessionId::new(1000, salt);

        //info!("r3= {:x?}", &s.get());
       // info!("r3= {:x?}", &s.get());
        //info!("r3= {:x?}", &s.get());
        //info!("r3= {:x?}", &s.get());

        info!("r4= {}", &s.get_b64());
        info!("r4= {}", &s.get_b64());
        info!("r4= {}", &s.get_b64());
        info!("r4= {}", &s.get_b64());

        assert_eq!(2 + 2, 4);

    }
}
