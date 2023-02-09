//use serde::{Serialize, Deserialize};
//use curve25519_dalek::ristretto::{RistrettoPoint, Scalar};
//use sha2::{Sha256, Digest};
//use std::convert::TryFrom;

use openssl::ec::{EcGroup, EcGroupRef, EcPoint, EcPointRef, PointConversionForm};
use openssl::bn::{BigNum, BigNumRef, BigNumContext, MsbOption};
use openssl::error::ErrorStack;
use openssl::hash::{hash, MessageDigest};




use std::convert::TryFrom;
use std::future::Future;
use std::pin::Pin;

pub fn hash_points(hash_id: MessageDigest, group: &EcGroupRef, points: &[EcPoint]) -> Result< BigNum, ErrorStack > {  //-> impl Future<Output = Result<u128, ()>> {
    
    //async move {

        let mut ctx = BigNumContext::new().unwrap();

        // bytes_points is a vec< [g.to_bytes, h.to_bytes]>
        let bytes_points: Vec<_> = points.iter().map(|p| p.to_bytes(group, PointConversionForm::COMPRESSED, &mut ctx).unwrap()).collect();

        // flatten bytes_points

        /* ====== as in .ts version
                
        // total size of bytes_points to create a new bytes vec

        let size : usize = bytes_points.iter().map(|b| b.len()).sum();
        let mut bytes = vec![0u8; size].into_boxed_slice();
        let mut offset = 0;

        for bp in &bytes_points {
            bytes[offset..offset + bp.len()].copy_from_slice(bp);
            offset += bp.len();
        }
        ==================================*/
        let flatten_bytes: Vec<_> = bytes_points.into_iter().flat_map(|x| x).collect();

        let hash = openssl::hash::hash(hash_id, &flatten_bytes[..]).map_err(|_| ()).unwrap();
        BigNum::from_slice(&hash[..10])
    //}
}

/* 
const bytesPoints = points.map((p) => p.toBytes()),
size = bytesPoints.map((b) => b.length).reduce((sum, cur) => sum + cur),
bytes = new Uint8Array(size)
let offset = 0
for (const bP of bytesPoints) {
bytes.set(bP, offset)
offset += bP.length
}
const buf = await crypto.subtle.digest(hashID, bytes),
hash = new Uint8Array(buf)
return fromBytes(hash.slice(0, 10))
retunr let bignum = BigNum::from_slice(&[0x12, 0x00, 0x34]).unwrap();    ---> my solutions
*/



//#[derive(Serialize, Deserialize)]
pub struct EqualityProof<'a> {
    pub group: &'a EcGroupRef,
    pub a_1: EcPoint,
    pub a_2: EcPoint,
    pub t_x: BigNum,
    pub t_r1: BigNum,
    pub t_r2: BigNum,
}

impl<'a> EqualityProof<'a> {
    fn eq(&self, other: &EqualityProof) -> bool {
        
        let mut ctx = BigNumContext::new().unwrap();

        self.a_1.eq(self.group, &other.a_1, &mut ctx).unwrap() &&
        self.a_2.eq(self.group, &other.a_2, &mut ctx).unwrap() &&
        self.t_x == other.t_x &&
        self.t_r1 == other.t_r1 &&
        self.t_r2 == other.t_r2
    }
}

/* 

fn hash_points(points: &[RistrettoPoint]) -> Scalar {
    let mut hasher = Sha256::new();
    for point in points {
        hasher.input(point.compress().as_bytes());
    }
    let result = hasher.result();
    Scalar::try_from(&result[..]).unwrap()
}

async fn prove_equality(
    params: PedersenParams,
    x: u64,
    C1: Commitment,
    C2: Commitment
) -> EqualityProof {
    let k = Scalar::random(&mut rand::thread_rng()),
        A1 = params.c * k,
        A2 = params.c * k,
        c = hash_points(&[C1.p, C2.p, A1, A2]),
        xx = Scalar::from(x),
        tx = k - c * xx,
        tr1 = A1.r - c * C1.r,
        tr2 = A2.r - c * C2.r;

    EqualityProof { A_1: A1, A_2: A2, t_x: tx, t_r1: tr1, t_r2: tr2 }
}

*/