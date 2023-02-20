use openssl::ec::{EcGroup, EcGroupRef, EcPoint, EcPointRef, PointConversionForm};
use openssl::bn::{BigNum, BigNumRef, BigNumContext, MsbOption};
use openssl::error::ErrorStack;
use openssl::hash::{hash, MessageDigest};

use crate::commit::pedersen::{Commitment, PedersenParams, generate_random};
use crate::curves::multimult::{MultiMult, Relation};
use crate::curves::mult::{MultProof};

use crate::equality::hash_points;




//#[derive(Serialize, Deserialize)]
pub struct PointAddProof<'a> {
    pub c_8: EcPoint,
    pub c_10: EcPoint,
    pub c_11: EcPoint,
    pub c_13: EcPoint,
    pub pi_8: MultProof,
    pub pi_10: MultProof,
    pub pi_11: MultProof,
    pub pi_13: MultProof,
    pub pi_x: EqualityProof,
    pub pi_y: EqualityProof,
}

impl<'a> PointAddProof<'a> {
    fn eq(&self, other: &PointAddProof) -> bool {
        
        let mut ctx = BigNumContext::new().unwrap();

        self.c_8.eq(self.group, &other.c_8, &mut ctx).unwrap() &&
        self.c_10.eq(self.group, &other.c_10, &mut ctx).unwrap() &&
        self.c_11.eq(self.group, &other.c_11, &mut ctx).unwrap() &&
        self.c_13.eq(self.group, &other.c_13, &mut ctx).unwrap() &&
        self.pi_8 == other.pi_8 &&
        self.pi_10 == other.pi_10 &&
        self.pi_11 == other.pi_11 &&
        self.pi_13 == other.pi_13 &&
        self.pi_x == other.pi_x &&
        self.pi_y == other.pi_y 
    }
}




/**
 * ZK(P, Q, R: R = P + Q)
 *
 * @param params
 * @param P (x1, y1)
 * @param Q (x2, y2)
 * @param R (x3, y3)
 * @param C1 x1 = PX
 * @param C2 x2 = QX
 * @param C3 x3 = RX
 * @param C4 y1 = PY
 * @param C5 y2 = QY
 * @param C6 y3 = RY
 */ 
pub fn prove_point_add<'a>(
    params: &'a PedersenParams<'a>,
    P: EcPoint,
    Q: EcPoint,
    R: EcPoint,
    PX: Commitment,
    PY: Commitment,
    QX: Commitment,
    QY: Commitment,
    RX: Commitment,
    RY: Commitment
) {//-> PointAddProof<'a> {

    let mut ctx = BigNumContext::new().unwrap();

    let mut order_curve = BigNum::new().unwrap();
    params.c.order(&mut order_curve, &mut ctx).unwrap();

    // Check P + Q = R
    let mut check_r = EcPoint::new(&self.group).unwrap();
    check_r.add(&params.c, &P, &Q, &mut ctx).unwrap();
    let equality =  R.eq(&params.c, &check_r, &mut ctx).unwrap()
    assert!(equality, "Points don't add up!");

    // Checks if points are at infinity
    let infinity_P = P.is_infinity(&params.c);
    assert!(infinity_P, "P is at infinity");
    let infinity_Q = Q.is_infinity(&params.c);
    assert!(infinity_Q, "Q is at infinity");
    let infinity_R = R.is_infinity(&params.c);
    assert!(infinity_R, "R is at infinity");

    let mut x1 = BigNum::new().unwrap();
    let mut y1 = BigNum::new().unwrap();
    let mut x2 = BigNum::new().unwrap();
    let mut y2 = BigNum::new().unwrap();
    let mut x3 = BigNum::new().unwrap();
    let mut _y3 = BigNum::new().unwrap();

    P.affine_coordinates(&params.c, &mut x1, &mut y1, &mut ctx).unwrap();
    Q.affine_coordinates(&params.c, &mut x2, &mut y2, &mut ctx).unwrap();
    R.affine_coordinates(&params.c, &mut x3, &mut _y3, &mut ctx).unwrap();

    let mut i_7 = BigNum::new().unwrap();
    i_7.mod_sub(&x2, &x1, &order_curve, &mut ctx).unwrap();         // i7  = x2 - x1
    let mut i_8 = BigNum::new().unwrap();
    i_8.mod_inverse(&i_7, &order_curve, &mut ctx).unwrap();         // i8  = (x2 - x1)^-1
    let mut i_9 = BigNum::new().unwrap();
    i_9.mod_sub(&y2, &y1, &order_curve, &mut ctx).unwrap();         // i9  = y2 - y1
    let mut i_10 = BigNum::new().unwrap();
    i_10.mod_mul(&i_8, &i_9, &order_curve, &mut ctx).unwrap();      // i10 = i8 * i9 =  (y2 - y1) / (x2 - x1)
    let mut i_11 = BigNum::new().unwrap();
    i_11.mod_mul(&i_10, &i_10, &order_curve, &mut ctx).unwrap();    // i11 = (i10)^2
    let mut i_12 = BigNum::new().unwrap();
    i_12.mod_sub(&x1, &x3, &order_curve, &mut ctx).unwrap();        // i12 = x1 - x3
    let mut i_13 = BigNum::new().unwrap();
    i_13.mod_mul(&i_10, &i_12, &order_curve, &mut ctx).unwrap();    // i13 = i10 * i12

/*     i7 = posMod(x2 - x1, order_curve), //    i7  = x2 - x1
    i8 = invMod(i7, order_curve), //         i8  = (x2 - x1)^-1
    i9 = posMod(y2 - y1, order_curve), //    i9  = y2 - y1
    i10 = posMod(i8 * i9, order_curve), //   i10 = i8 * i9 =  (y2 - y1) / (x2 - x1)
    i11 = posMod(i10 * i10, order_curve), // i11 = (i10)^2
    i12 = posMod(x1 - x3, order_curve), //   i12 = x1 - x3
    i13 = posMod(i10 * i12, order_curve), // i13 = i10 * i12 */

}


