// use std::error::Error;
use openssl::ec::{EcGroup, EcPoint};
use openssl::nid::Nid;
use openssl::bn::{BigNum, BigNumRef, BigNumContext, MsbOption};
use openssl::hash::MessageDigest;

mod commit; 
mod curves;
mod exp;
mod signature;

pub use crate::commit::{pedersen, equality, mult};
pub use crate::exp::pointAdd::{prove_point_add, verify_point_add};
pub use crate::exp::exp::{padded_bits, generate_indices, prov_exp, verify_exp}; 



fn main() {
    println!("Hello, world!");

    let mut ctx = BigNumContext::new().unwrap();

    // ========================== Testing units ==========================

    // Create a new P256 curve object
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();

    // Creat new T256 curve object
                /*  export const war256 = new WeierstrassGroup(
                'war256',
                BigInt('0xffffffff0000000100000000000000017e72b42b30e7317793135661b1c4b117'),   // p
                BigInt('0xffffffff0000000100000000000000017e72b42b30e7317793135661b1c4b114'),   // a 
                BigInt('0xb441071b12f4a0366fb552f8e21ed4ac36b06aceeb354224863e60f20219fc56'),   // b
                BigInt('0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff'),   // order
                [BigInt('0x3'), BigInt('0x5a6dd32df58708e64e97345cbe66600decd9d538a351bb3c30b4954925b1f02d')]   // generator
            ) */

    let p = BigNum::from_hex_str("ffffffff0000000100000000000000017e72b42b30e7317793135661b1c4b117").unwrap();
    let a = BigNum::from_hex_str("ffffffff0000000100000000000000017e72b42b30e7317793135661b1c4b114").unwrap();
    let b = BigNum::from_hex_str("b441071b12f4a0366fb552f8e21ed4ac36b06aceeb354224863e60f20219fc56").unwrap();
    let tom_order = BigNum::from_hex_str("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff").unwrap();
    let tom_g_x = BigNum::from_hex_str("3").unwrap();
    let tom_g_y = BigNum::from_hex_str("5a6dd32df58708e64e97345cbe66600decd9d538a351bb3c30b4954925b1f02d").unwrap();

    // create tom group
    let mut tom_group = EcGroup::from_components(p, a, b,&mut ctx).unwrap();

    // create generator
    let mut tom_g = EcPoint::new(&tom_group).unwrap();
    tom_g.set_affine_coordinates_gfp(&tom_group, &tom_g_x, &tom_g_y, &mut ctx).unwrap();

    // set generator and order on group
    tom_group.set_generator(tom_g, tom_order, BigNum::from_u32(1).unwrap());

    // ========================== pedersen.rs ==========================
    { // =========================== add ===============================
        // Generate two points randomly
        let point1 = EcPoint::new(&group).unwrap();
        let point2 = EcPoint::new(&group).unwrap();

        let bign43 = BigNum::from_dec_str("43").unwrap();
        let bign2 = BigNum::from_dec_str("2").unwrap();

        let mut c1 = pedersen::Commitment::new(&group, point1, bign43);
        let c2 = pedersen::Commitment::new(&group, point2, bign2);
        let c3 = c1.add(&c2);

        println!("The result of adding commitments is {} = 45?", c3.r);
    }

    { // =========================== sub ===============================
        // Generate two points randomly
        let point1 = EcPoint::new(&group).unwrap();
        let point2 = EcPoint::new(&group).unwrap();

        let bign43 = BigNum::from_dec_str("43").unwrap();
        let bign2 = BigNum::from_dec_str("2").unwrap();

        let mut c1 = pedersen::Commitment::new(&group, point1, bign43);
        let c2 = pedersen::Commitment::new(&group, point2, bign2);
        let c3 = c1.sub(&c2);

        println!("The result of adding commitments is {} = 41?", c3.r);
    }

    { // =========================== mul ===============================
        // Generate one point randomly
        let point1 = EcPoint::new(&group).unwrap();

        let bign43 = BigNum::from_dec_str("43").unwrap();
        let bign2 = BigNum::from_dec_str("2").unwrap();

        let mut c1 = pedersen::Commitment::new(&group, point1, bign43);
        let c3 = c1.mul(&bign2);

        println!("The result of adding commitments is {} = 86?", c3.r);
    }


    { // =========================== new ===============================
        let g = EcPoint::new(&group).unwrap();
        let h = EcPoint::new(&group).unwrap();
        let pp = pedersen::PedersenParams::new(&group, g, h);
        
        let bign101 = BigNum::from_dec_str("101").unwrap();
        pp.commit(&bign101);
    }


    { // ================= generate_pedersen_params ====================
        let pp = pedersen::generate_pedersen_params(&group);
        
        let bign101 = BigNum::from_dec_str("101").unwrap();
        pp.commit(&bign101);
    }

    { // =========================== eq ===============================
        let pp_1 = pedersen::generate_pedersen_params(&group);
        let pp_2 = pedersen::generate_pedersen_params(&group);
    
        let bool_false = pp_1.eq(&pp_2);
        let bool_true = pp_1.eq(&pp_1);

        assert_eq!(bool_false, false);
        assert_eq!(bool_true, true);
    }
    

    // ========================== equality.rs ==========================

    {
        
        let mut ctx = BigNumContext::new().unwrap();

        let g = group.generator();
        
        let mut order_curve = BigNum::new().unwrap();
        group.order(&mut order_curve, &mut ctx).unwrap();
        let r = pedersen::generate_random(&order_curve).unwrap();

        // println!("Size is: {:?}", r);
        
        let mut h = EcPoint::new(&group).unwrap();
        h.mul(&group, &g, &r, &mut ctx).unwrap();

        let hash_value = equality::hash_points(MessageDigest::sha256(), &[&group], &[&g.to_owned(&group).unwrap(), &h]).unwrap();
        println!("hash_value is: {:?}", hash_value);

    }

    {
        let g = EcPoint::new(&group).unwrap();
        let infinity = g.is_infinity(&group);
        println!("EcPoint initialized at infinity: {}", infinity);
    }

    {  // Check invert is the same as multiply by -1
        //Generate random point::
        let mut ctx = BigNumContext::new().unwrap();
        let g = group.generator();
        let mut order_curve = BigNum::new().unwrap();
        group.order(&mut order_curve, &mut ctx);
        let r = pedersen::generate_random(&order_curve).unwrap();
        let mut h = EcPoint::new(&group).unwrap();
        h.mul(&group, &g, &r, &mut ctx).unwrap();



        // Multiply by -1
        let minus_1 = BigNum::from_dec_str("-1").unwrap(); 
        let mut minus_h = EcPoint::new(&group).unwrap();
        minus_h.mul(&group, &h, &minus_1, &mut ctx).unwrap();

        //use invert
        h.invert(&group, &mut ctx).unwrap();

        let invertibility = h.eq(&group, &minus_h, &mut ctx).unwrap();

        println!("h.inv == -h is: {}", invertibility);

    }

    {       // ====== CHECK THE EQUALITY FUNCTIONS ====== //

        let pparams = pedersen::generate_pedersen_params(&group);
        
        let same_bign10 = BigNum::from_dec_str("10").unwrap();
        //let same_bign10 = BigNum::from_dec_str("10").unwrap();
        let diff_bign11 = BigNum::from_dec_str("11").unwrap();
        
        // ============== Generate commitments & points
        // commitments
        let com_1_same_bign10 = pparams.commit(&same_bign10);
        let com_2_same_bign10 = pparams.commit(&same_bign10);
        // points
        let com_1_same_bign10_point = com_1_same_bign10.p.to_owned(&group).unwrap();
        let com_2_same_bign10_point = com_2_same_bign10.p.to_owned(&group).unwrap();

        // commitments
        let com_1_diff_bign10 = pparams.commit(&same_bign10);
        let com_2_diff_bign11 = pparams.commit(&diff_bign11);
        // points
        let com_1_diff_bign10_point = com_1_diff_bign10.p.to_owned(&group).unwrap();
        let com_2_diff_bign11_point = com_2_diff_bign11.p.to_owned(&group).unwrap();


        // ============== Test true 

        let pi_eq_same = equality::prove_equality(&pparams, same_bign10, com_1_same_bign10, com_2_same_bign10);

        let ver_eq_true = equality::verify_equality(&pparams, com_1_same_bign10_point, com_2_same_bign10_point, &pi_eq_same);
        println!("The true equality test is: {}", ver_eq_true);
        assert_eq!(ver_eq_true, true);


        // ============== Test false 

        let pi_eq_diff = equality::prove_equality(&pparams, diff_bign11, com_1_diff_bign10, com_2_diff_bign11);

        let ver_eq_false = equality::verify_equality(&pparams, com_1_diff_bign10_point, com_2_diff_bign11_point, &pi_eq_diff);
        println!("The false equality test is: {}", ver_eq_false);
        assert_eq!(ver_eq_false, false);

    }

    {   // ====== CHECK THE MULT FUNCTIONS ====== //

        // ZK(x, y, z, rx, ry, rz: z = x * y and Cx = xG + rx H and Cy = yG + ry H and Cz = zG + rz H)
 
        let pparams = pedersen::generate_pedersen_params(&tom_group);
        
        // Generate numbers
        let x = BigNum::from_dec_str("2").unwrap();         // x = 2
        let y = BigNum::from_dec_str("3").unwrap();         // y = 3
        let z = BigNum::from_dec_str("6").unwrap();         // z = x * y = 6
        let z_diff = BigNum::from_dec_str("7").unwrap();    // z != x * y

        // Generate commitments
        let com_x = pparams.commit(&x);
        let com_y = pparams.commit(&y);
        let com_z = pparams.commit(&z);
        let com_z_diff = pparams.commit(&z_diff);
        
        // ============== Test true 
        let pi_mult_true = mult::prov_mult(&pparams, 
                                            x.to_owned().unwrap(), 
                                            y.to_owned().unwrap(), 
                                            z.to_owned().unwrap(), 
                                            com_x.to_owned(), 
                                            com_y.to_owned(), 
                                            com_z.to_owned());

        let ver_mult_true = mult::verify_mult(&pparams, 
                                            com_x.p.to_owned(&pparams.c).unwrap(), 
                                            com_y.p.to_owned(&pparams.c).unwrap(),
                                            com_z.p.to_owned(&pparams.c).unwrap(),
                                            &pi_mult_true);

        println!("The true mult test is: {}", ver_mult_true);
        assert_eq!(ver_mult_true, true);

        // ============== Test false 
        let pi_mult_false = mult::prov_mult(&pparams, 
                                        x.to_owned().unwrap(), 
                                        y.to_owned().unwrap(), 
                                        z_diff.to_owned().unwrap(), 
                                        com_x.to_owned(), 
                                        com_y.to_owned(), 
                                        com_z_diff.to_owned());

        let ver_mult_false = mult::verify_mult(&pparams, 
                                        com_x.p.to_owned(&pparams.c).unwrap(), 
                                        com_y.p.to_owned(&pparams.c).unwrap(),
                                        com_z_diff.p.to_owned(&pparams.c).unwrap(),
                                        &pi_mult_true);

        println!("The false mult test is: {}", ver_mult_false);
        assert_eq!(ver_mult_false, false);



    }

    { 
        let mut ctx = BigNumContext::new().unwrap();

        let mut order_curve = BigNum::new().unwrap();
        group.order(&mut order_curve, &mut ctx).unwrap();

        let bign_minus10 = BigNum::from_dec_str("-10").unwrap();

        let mut cc = BigNum::new().unwrap();
        cc.nnmod(&bign_minus10, &order_curve, &mut ctx).unwrap();

        println!("-10 mod order_curve = {} > 0", cc);
    }

    {       // ====== CHECK THE pointAdd FUNCTIONS ====== //

        let mut ctx = BigNumContext::new().unwrap();

        let pparams = pedersen::generate_pedersen_params(&group);
        let tom_pparams = pedersen::generate_pedersen_params(&tom_group);
        
        let g = group.generator();

        let mut order_curve = BigNum::new().unwrap();
        group.order(&mut order_curve, &mut ctx).unwrap();
        
        // ============== Generate commitments & points

        // P + Q = R
        
        // =======              P
        let mut P = EcPoint::new(&pparams.c).unwrap();
        let r = pedersen::generate_random(&order_curve).unwrap();        
        P.mul(&group, &g, &r, &mut ctx).unwrap();

        // commitment PX, PY
        let mut x1 = BigNum::new().unwrap();
        let mut y1 = BigNum::new().unwrap();
    
        P.affine_coordinates_gfp(&pparams.c, &mut x1, &mut y1, &mut ctx).unwrap();
        let PX = tom_pparams.commit(&x1);
        let PY = tom_pparams.commit(&y1);

        let PX_point = PX.p.to_owned(&tom_pparams.c).unwrap();
        let PY_point = PY.p.to_owned(&tom_pparams.c).unwrap();


         // =======              Q
         let mut Q = EcPoint::new(&pparams.c).unwrap();
         let r = pedersen::generate_random(&order_curve).unwrap();        
         Q.mul(&group, &g, &r, &mut ctx).unwrap();
 
         // commitment QX, QY
         let mut x2 = BigNum::new().unwrap();
         let mut y2 = BigNum::new().unwrap();
     
         Q.affine_coordinates_gfp(&pparams.c, &mut x2, &mut y2, &mut ctx).unwrap();
         let QX = tom_pparams.commit(&x2);
         let QY = tom_pparams.commit(&y2);

        let QX_point = QX.p.to_owned(&tom_pparams.c).unwrap();
        let QY_point = QY.p.to_owned(&tom_pparams.c).unwrap();     


         // =======              R
         let mut R = EcPoint::new(&pparams.c).unwrap();
        R.add(&pparams.c, &P, &Q, &mut ctx).unwrap();

         
         // commitment RX, RY
         let mut x3 = BigNum::new().unwrap();
         let mut y3 = BigNum::new().unwrap();
     
         R.affine_coordinates_gfp(&pparams.c, &mut x3, &mut y3, &mut ctx).unwrap();
         let RX = tom_pparams.commit(&x3);
         let RY = tom_pparams.commit(&y3);  

         let RX_point = RX.p.to_owned(&tom_pparams.c).unwrap();
         let RY_point = RY.p.to_owned(&tom_pparams.c).unwrap();


        // ============== Test true 

        let pi_point_add = prove_point_add(&pparams, &tom_pparams, P, Q, R, PX, PY, QX, QY, RX, RY);

        let ver_pa_true = verify_point_add(&tom_pparams, PX_point, PY_point, QX_point, QY_point, RX_point, RY_point, &pi_point_add);
        println!("pointAdd proof is working: {}", ver_pa_true);
        assert_eq!(ver_pa_true, true);

    }

    {// ============ Test Exp aux functions

        let mut bign_11_binary_1011 = BigNum::from_dec_str("11").unwrap();

        let paddedBits = padded_bits(&bign_11_binary_1011, 8);

        println!{"Vector is {:?}", paddedBits};

        let vec_shuffled = generate_indices(5);

        println!("Shuffled vector is: {vec_shuffled:?}");
        
        
    }

{       // ====== CHECK THE EXP FUNCTIONS ====== //

    let mut ctx = BigNumContext::new().unwrap();

    let nist_params = pedersen::generate_pedersen_params(&group);
    let tom_params = pedersen::generate_pedersen_params(&tom_group);
    
    let nist_g = group.generator();
    let tom_g = tom_group.generator();

    let mut nist_order = BigNum::new().unwrap();
    group.order(&mut nist_order, &mut ctx).unwrap();

    let mut tom_order = BigNum::new().unwrap();
    tom_group.order(&mut tom_order, &mut ctx).unwrap();
    
    // ============== Generate commitments & points

    // (x, y) = lambda g = P
    
    let secparam = 80;

    // commitment lambda
    let lambda = pedersen::generate_random(&nist_order).unwrap(); 
    let Clambda = nist_params.commit(&lambda);

    // =======              P = lambda g
    let mut P = EcPoint::new(&nist_params.c).unwrap();
    P.mul(&group, &nist_g, &lambda, &mut ctx).unwrap();

    // commitment PX, PY
    let mut x = BigNum::new().unwrap();
    let mut y = BigNum::new().unwrap();

    P.affine_coordinates_gfp(&nist_params.c, &mut x, &mut y, &mut ctx).unwrap();
    let PX = tom_params.commit(&x);
    let PY = tom_params.commit(&y);

    let PX_point = PX.p.to_owned(&tom_params.c).unwrap();
    let PY_point = PY.p.to_owned(&tom_params.c).unwrap();


    // ============== Test true 

    let pi_point_add = prov_exp(
        &nist_params, 
        &tom_params, 
        lambda, 
        Clambda.to_owned(),
        P.to_owned(&nist_params.c).unwrap(),
        PX.to_owned(),
        PY.to_owned(),
        secparam,
        None
    );

/*     paramsNIST: &'a PedersenParams<'a>,
    paramsWario: &'a PedersenParams<'a>,
    Clambda : EcPoint,
    Px: EcPoint,
    Py: EcPoint,
    pi: &'a Vec<ExpProof<'a>>,
    secparam: usize,
    Q: Option<EcPoint>, */

    let ver_exp_true = verify_exp(
        &nist_params, 
        &tom_params, 
        Clambda.p,
        PX_point,
        PY_point,
        &pi_point_add,
        secparam,
        None
    );

    println!("verifyExp proof is working: {}", ver_exp_true);
    assert_eq!(ver_exp_true, true);

}


}
