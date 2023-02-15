// use std::error::Error;
use openssl::ec::{EcGroup, EcPoint};
use openssl::nid::Nid;
use openssl::bn::{BigNum, BigNumRef, BigNumContext, MsbOption};
use openssl::hash::MessageDigest;

mod commit; 
mod curves;

pub use crate::commit::{pedersen, equality};



fn main() {
    println!("Hello, world!");



    // ========================== Testing units ==========================

    // Create a new P256 curve object
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();

    // ========================== pedersen.rs ==========================
    { // =========================== add ===============================
        // Generate two points randomly
        let point1 = EcPoint::new(&group).unwrap();
        let point2 = EcPoint::new(&group).unwrap();

        let bign43 = BigNum::from_dec_str("43").unwrap();
        let bign2 = BigNum::from_dec_str("2").unwrap();

        let mut c1 = pedersen::Commitment::new(&group, point1, bign43);
        let c2 = pedersen::Commitment::new(&group, point2, bign2);
        c1.add(&c2);

        println!("The result of adding commitments is {} = 45?", c1.r);
    }

    { // =========================== sub ===============================
        // Generate two points randomly
        let point1 = EcPoint::new(&group).unwrap();
        let point2 = EcPoint::new(&group).unwrap();

        let bign43 = BigNum::from_dec_str("43").unwrap();
        let bign2 = BigNum::from_dec_str("2").unwrap();

        let mut c1 = pedersen::Commitment::new(&group, point1, bign43);
        let c2 = pedersen::Commitment::new(&group, point2, bign2);
        c1.sub(&c2);

        println!("The result of adding commitments is {} = 41?", c1.r);
    }

    { // =========================== mul ===============================
        // Generate one point randomly
        let point1 = EcPoint::new(&group).unwrap();

        let bign43 = BigNum::from_dec_str("43").unwrap();
        let bign2 = BigNum::from_dec_str("2").unwrap();

        let mut c1 = pedersen::Commitment::new(&group, point1, bign43);
        c1.mul(&bign2);

        println!("The result of adding commitments is {} = 86?", c1.r);
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
        group.order(&mut order_curve, &mut ctx);
        let r = pedersen::generate_random(&order_curve).unwrap();

        // println!("Size is: {:?}", r);
        
        let mut h = EcPoint::new(&group).unwrap();
        h.mul(&group, &g, &r, &mut ctx).unwrap();

        let hash_value = equality::hash_points(MessageDigest::sha256(), &group, &[&g.to_owned(&group).unwrap(), &h]).unwrap();
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
        h.invert(&group, &mut ctx);

        let invertibility = h.eq(&group, &minus_h, &mut ctx).unwrap();

        println!("h.inv == -h is: {}", invertibility);

    }

    {       // ====== CHECK THE EQUALITY FUNCTIONS ====== //

            // TODO
    }

}
