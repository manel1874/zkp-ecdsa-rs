use openssl::ec::{EcGroup, EcGroupRef, EcPoint, EcPointRef, PointConversionForm};
use openssl::bn::{BigNum, BigNumRef, BigNumContext, MsbOption};
use openssl::error::ErrorStack;
use openssl::hash::{hash, MessageDigest};

use crate::commit::pedersen::{Commitment, PedersenParams, generate_random};
use crate::commit::mult::{MultProof, prov_mult, aggregate_mult};
use crate::commit::equality::{EqualityProof, prove_equality, aggregate_equality};
use crate::curves::multimult::{MultiMult, Relation};

use crate::equality::hash_points;




//#[derive(Serialize, Deserialize)]
pub struct PointAddProof<'a> {
    pub group: &'a EcGroupRef,
    pub c_8: EcPoint,
    pub c_10: EcPoint,
    pub c_11: EcPoint,
    pub c_13: EcPoint,
    pub pi_8: MultProof<'a>,
    pub pi_10: MultProof<'a>,
    pub pi_11: MultProof<'a>,
    pub pi_13: MultProof<'a>,
    pub pi_x: EqualityProof<'a>,
    pub pi_y: EqualityProof<'a>,
}

impl<'a> PointAddProof<'a> {
    fn eq(&self, other: &PointAddProof) -> bool {
        
        let mut ctx = BigNumContext::new().unwrap();

        self.c_8.eq(self.group, &other.c_8, &mut ctx).unwrap() &&
        self.c_10.eq(self.group, &other.c_10, &mut ctx).unwrap() &&
        self.c_11.eq(self.group, &other.c_11, &mut ctx).unwrap() &&
        self.c_13.eq(self.group, &other.c_13, &mut ctx).unwrap() &&
        self.pi_8.eq(&other.pi_8) &&
        self.pi_10.eq(&other.pi_10) &&
        self.pi_11.eq(&other.pi_11) &&
        self.pi_13.eq(&other.pi_13) &&
        self.pi_x.eq(&other.pi_x) &&
        self.pi_y.eq(&other.pi_y) 
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
    paramsNIST: &'a PedersenParams<'a>,
    paramsWario: &'a PedersenParams<'a>,
    P: EcPoint,
    Q: EcPoint,
    R: EcPoint,
    PX: Commitment,
    PY: Commitment,
    QX: Commitment,
    QY: Commitment,
    RX: Commitment,
    RY: Commitment
) -> PointAddProof<'a> {

    let mut ctx = BigNumContext::new().unwrap();

    // Check P + Q = R
    let mut check_r = EcPoint::new(&paramsNIST.c).unwrap();
    check_r.add(&paramsNIST.c, &P, &Q, &mut ctx).unwrap();
    let equality =  R.eq(&paramsNIST.c, &check_r, &mut ctx).unwrap();
    assert!(equality, "Points don't add up!");

    // Checks if points are at infinity
    let infinity_P = P.is_infinity(&paramsNIST.c);
    assert!(!infinity_P, "P is at infinity");
    let infinity_Q = Q.is_infinity(&paramsNIST.c);
    assert!(!infinity_Q, "Q is at infinity");
    let infinity_R = R.is_infinity(&paramsNIST.c);
    assert!(!infinity_R, "R is at infinity");

    let mut x1 = BigNum::new().unwrap();
    let mut y1 = BigNum::new().unwrap();
    let mut x2 = BigNum::new().unwrap();
    let mut y2 = BigNum::new().unwrap();
    let mut x3 = BigNum::new().unwrap();
    let mut _y3 = BigNum::new().unwrap();

    P.affine_coordinates_gfp(&paramsNIST.c, &mut x1, &mut y1, &mut ctx).unwrap();
    Q.affine_coordinates_gfp(&paramsNIST.c, &mut x2, &mut y2, &mut ctx).unwrap();
    R.affine_coordinates_gfp(&paramsNIST.c, &mut x3, &mut _y3, &mut ctx).unwrap();

    let C1 = PX.to_owned();
    let C2 = QX.to_owned();
    let C3 = RX.to_owned();
    let C4 = PY.to_owned();
    let C5 = QY.to_owned();
    let C6 = RY.to_owned();


    let mut order_curve = BigNum::new().unwrap();
    paramsWario.c.order(&mut order_curve, &mut ctx).unwrap();


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


    let C7 = C2.sub(&C1);
    let C8 = paramsWario.commit(&i_8);
    let C9 = C5.sub(&C4);
    let C10 = paramsWario.commit(&i_10);
    let C11 = paramsWario.commit(&i_11);
    let C12 = C1.sub(&C3);
    let C13 = paramsWario.commit(&i_13);
    let C14 = Commitment::new(&paramsWario.c, paramsWario.g.to_owned(&paramsWario.c).unwrap(), BigNum::from_u32(0).unwrap());

    let pi_8 = prov_mult(&paramsWario, 
        i_7, 
        i_8.to_owned().unwrap(),
        BigNum::from_u32(1).unwrap(),
        C7,
        C8.to_owned(),
        C14
    );

    // pi10 => i10 = i8 * i9
    let pi_10 = prov_mult(&paramsWario, 
        i_8, 
        i_9,
        i_10.to_owned().unwrap(),
        C8.to_owned(),
        C9,
        C10.to_owned()
    );

    // pi11 => i11 = i10 * i10
    let pi_11 = prov_mult(&paramsWario, 
        i_10.to_owned().unwrap(), 
        i_10.to_owned().unwrap(),
        i_11.to_owned().unwrap(),
        C10.to_owned(),
        C10.to_owned(),
        C11.to_owned()
    );

    // CHECKING HERE!!!!!!!!!!!!

    //  Cint = Commitment(C3.p.add(C1.p).add(C2.p), C3.r.add(C1.r).add(C2.r))
    let mut cint_p = EcPoint::new(&paramsWario.c).unwrap();
    let mut cint_p_int = EcPoint::new(&paramsWario.c).unwrap();
    cint_p_int.add(&paramsWario.c, &C1.p, &C2.p, &mut ctx).unwrap();
    cint_p.add(&paramsWario.c, &cint_p_int, &C3.p, &mut ctx).unwrap();

    let mut cint_r = BigNum::new().unwrap();
    let mut cint_r_int = BigNum::new().unwrap();
    cint_r_int.mod_add(&C1.r, &C2.r, &order_curve, &mut ctx).unwrap();
    cint_r.mod_add(&cint_r_int, &C3.r, &order_curve, &mut ctx).unwrap();

    let Cint = Commitment::new(&paramsWario.c, cint_p, cint_r);

    // pix => x3 = i11 - x1 - x2
    let pi_x = prove_equality(&paramsWario,
        i_11,
        C11.to_owned(),
        Cint
    ); 

    // pi12 => i12 = x1 - x3
    // pi13 => i13 = i10 * i12
    let pi_13 = prov_mult(&paramsWario,
        i_10,
        i_12,
        i_13.to_owned().unwrap(),
        C10.to_owned(),
        C12,
        C13.to_owned(),
    );

    //  Cint = new Commitment(C6.p.add(C4.p), C6.r.add(C4.r))
    let mut cint_p = EcPoint::new(&paramsWario.c).unwrap();
    cint_p.add(&paramsWario.c, &C6.p, &C4.p, &mut ctx).unwrap();

    let mut cint_r = BigNum::new().unwrap();
    cint_r.mod_add(&C6.r, &C4.r, &order_curve, &mut ctx).unwrap();

    let Cint = Commitment::new(&paramsWario.c, cint_p, cint_r); 

    // piy => y3 = i13 - y1
    let pi_y = prove_equality(&paramsWario,
        i_13,
        C13.to_owned(),
        Cint
    );

    PointAddProof {
        group: paramsWario.c,
        c_8: C8.p,
        c_10: C10.p,
        c_11: C11.p,
        c_13: C13.p,
        pi_8,
        pi_10,
        pi_11,
        pi_13,
        pi_x,
        pi_y
    }
}

/**
 * ZKP Verification ZK(P, Q, R: P + Q = R)
 * P (x1, y1)
 * Q (x2, y2)
 * R (x3, y3)
 *
 * @param params
 * @param C1 x1
 * @param C2 x2
 * @param C3 x3
 * @param C4 y1
 * @param C5 y2
 * @param C6 y3
 * @param pi
 * @param challenge
 */

 pub fn verify_point_add<'a>(
    params: &'a PedersenParams<'a>,
    PX: EcPoint,
    PY: EcPoint,
    QX: EcPoint,
    QY: EcPoint,
    RX: EcPoint,
    RY: EcPoint,
    pi: &'a PointAddProof<'a>
) -> bool {
    
    let mut multi = MultiMult::new(params.c);
    let ok = aggregate_point_add(params, PX, PY, QX, QY, RX, RY, pi, &mut multi);

    if !ok {
        return false
    }
    
    multi.evaluate().is_infinity(&params.c)
}


pub fn aggregate_point_add<'a> (
    params: &'a PedersenParams<'a>,
    PX: EcPoint,
    PY: EcPoint,
    QX: EcPoint,
    QY: EcPoint,
    RX: EcPoint,
    RY: EcPoint,
    pi: &'a PointAddProof<'a>,
    multi: &mut MultiMult
) -> bool {

    let mut ctx = BigNumContext::new().unwrap();

    let C1 = PX.to_owned(&params.c).unwrap();
    let C2 = QX.to_owned(&params.c).unwrap();
    let C3 = RX.to_owned(&params.c).unwrap();
    let C4 = PY.to_owned(&params.c).unwrap();
    let C5 = QY.to_owned(&params.c).unwrap();
    let C6 = RY.to_owned(&params.c).unwrap();
    
    // let C7 = C2.sub(&C1);
    let mut C7 = EcPoint::new(&params.c).unwrap();
    let mut minus_C1 = C1.to_owned(&params.c).unwrap();
    minus_C1.invert(&params.c, &mut ctx).unwrap();
    C7.add(&params.c, &C2, &minus_C1, &mut ctx).unwrap();
    
    // let C9 = C5.sub(&C4);
    let mut C9 = EcPoint::new(&params.c).unwrap();
    let mut minus_C4 = C4.to_owned(&params.c).unwrap();
    minus_C4.invert(&params.c, &mut ctx).unwrap();
    C9.add(&params.c, &C5, &minus_C4, &mut ctx).unwrap();

    // let C12 = C1.sub(&C3);
    let mut C12 = EcPoint::new(&params.c).unwrap();
    let mut minus_C3 = C3.to_owned(&params.c).unwrap();
    minus_C3.invert(&params.c, &mut ctx).unwrap();
    C12.add(&params.c, &C1, &minus_C3, &mut ctx).unwrap();


    // pi8 => C8 * C7 = C14 and C14 == 1
    let c_14 = params.g.to_owned(&params.c).unwrap();
    let c_8 = pi.c_8.to_owned(&params.c).unwrap();
    let ver_aggmult = aggregate_mult(&params, C7, c_8, c_14, &pi.pi_8, multi);
    if !ver_aggmult {
        println!("Failed on proof pi8.");
        return false;
    }

    // pi10 => i10 = i8 * i9
    let c_8 = pi.c_8.to_owned(&params.c).unwrap();
    let c_10 = pi.c_10.to_owned(&params.c).unwrap();
    let ver_aggmult = aggregate_mult(&params, c_8, C9, c_10, &pi.pi_10, multi);
    if !ver_aggmult {
        println!("Failed on proof pi10.");
        return false;
    }

    // pi11 => i11 = i10 * i10
    let c_10_1 = pi.c_10.to_owned(&params.c).unwrap();
    let c_10_2 = pi.c_10.to_owned(&params.c).unwrap();
    let c_11 = pi.c_11.to_owned(&params.c).unwrap();
    let ver_aggmult = aggregate_mult(&params, c_10_1, c_10_2, c_11, &pi.pi_11, multi);
    if !ver_aggmult {
        println!("Failed on proof pi11.");
        return false;
    }

    // pix => x3 = i11 - x1 - x2
    let mut cint = EcPoint::new(&params.c).unwrap();
    let mut cint_int = EcPoint::new(&params.c).unwrap();
    cint_int.add(&params.c, &C1, &C2, &mut ctx).unwrap();
    cint.add(&params.c, &cint_int, &C3, &mut ctx).unwrap();
    let c_11 = pi.c_11.to_owned(&params.c).unwrap();
    let ver_aggeq = aggregate_equality(&params, c_11, cint, &pi.pi_x, multi);
    if !ver_aggeq {
        println!("Failed on proof pix.");
        return false;
    }

    // pi13 => i13 = i10 * i12
    let c_10 = pi.c_10.to_owned(&params.c).unwrap();
    let c_13 = pi.c_13.to_owned(&params.c).unwrap();
    let ver_aggmult = aggregate_mult(&params, c_10, C12, c_13, &pi.pi_13, multi);
    if !ver_aggmult {
        println!("Failed on proof pi13.");
        return false;
    }

    // piy => y3 = i13 - y1
    let mut cint = EcPoint::new(&params.c).unwrap();
    cint.add(&params.c, &C4, &C6, &mut ctx).unwrap();
    let c_13 = pi.c_13.to_owned(&params.c).unwrap();
    let ver_aggeq = aggregate_equality(&params, c_13, cint, &pi.pi_y, multi);
    if !ver_aggeq {
        println!("Failed on proof piy.");
        return false;
    }

    true

}

