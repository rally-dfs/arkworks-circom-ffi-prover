mod witness;

use std::ffi::CString;
use std::io::Cursor;
use std::os::raw::{c_char, c_int};
use std::{mem, slice};

use ark_bn254::Bn254;
use ark_circom::circom::CircomReduction;
use ark_circom::ethereum::Proof;
use ark_circom::read_zkey;
use ark_crypto_primitives::snark::SNARK;
use ark_groth16::Groth16;
use ark_std::rand::thread_rng;
use ark_std::UniformRand;
use libc::size_t;

#[no_mangle]
unsafe extern "C" fn prove_rs(
    w: *const u8,
    w_len: size_t,
    z: *const u8,
    z_len: size_t,
) -> *mut *mut c_char {
    let mut witness = unsafe {
        assert!(!w.is_null());
        slice::from_raw_parts(w, w_len)
    };

    let zkey = unsafe {
        assert!(!z.is_null());
        slice::from_raw_parts(z, z_len)
    };

    let mut zkey_cursor = Cursor::new(zkey);

    let (pk, matrices) = read_zkey(&mut zkey_cursor).unwrap();
    let num_inputs = matrices.num_instance_variables;
    let num_constraints = matrices.num_constraints;

    let mut rng = thread_rng();
    let r = ark_bn254::Fr::rand(&mut rng);
    let s = ark_bn254::Fr::rand(&mut rng);

    let full_assignment = witness::witness_assignments::<Bn254, _>(&mut witness).unwrap();

    let proof = Groth16::<Bn254, CircomReduction>::create_proof_with_reduction_and_matrices(
        &pk,
        r,
        s,
        &matrices,
        num_inputs,
        num_constraints,
        full_assignment.as_slice(),
    )
    .unwrap();

    // let public_signals: Vec<String> = full_assignment[1..num_inputs]
    //     .iter()
    //     .map(|i| i.to_string())
    //     .collect::<Vec<_>>();

    // println!("full assignment: {:?}", public_signals);

    let pvk = Groth16::<Bn254>::process_vk(&pk.vk).unwrap();
    let inputs = &full_assignment[1..num_inputs];
    let verified = Groth16::<Bn254>::verify_with_processed_vk(&pvk, inputs, &proof).unwrap();
    assert!(verified);

    let v = proof_to_cstrings(proof.clone());

    let (ptr, _len) = build_string_array(v);

    ptr
}

fn proof_to_cstrings(proof: ark_groth16::Proof<Bn254>) -> Vec<CString> {
    let mut v = Vec::with_capacity(8);

    let p = Proof::from(proof);

    // Let's fill a vector with null-terminated strings
    v.push(CString::new(p.a.x.to_string()).unwrap());
    v.push(CString::new(p.a.y.to_string()).unwrap());
    v.push(CString::new(p.b.x[1].to_string()).unwrap());
    v.push(CString::new(p.b.x[0].to_string()).unwrap());
    v.push(CString::new(p.b.y[1].to_string()).unwrap());
    v.push(CString::new(p.b.y[0].to_string()).unwrap());
    v.push(CString::new(p.c.x.to_string()).unwrap());
    v.push(CString::new(p.c.y.to_string()).unwrap());

    v
}

fn build_string_array(v: Vec<CString>) -> (*mut *mut c_char, c_int) {
    let len = v.len();

    // Turning each null-terminated string into a pointer.
    // `into_raw` takes ownershop, gives us the pointer and does NOT drop the data.
    let mut out = v.into_iter().map(|s| s.into_raw()).collect::<Vec<_>>();

    // Make sure we're not wasting space.
    out.shrink_to_fit();
    assert!(out.len() == out.capacity());

    // Get the pointer to our vector.
    let ptr = out.as_mut_ptr();
    mem::forget(out);

    (ptr, len as c_int)
}

#[no_mangle]
unsafe extern "C" fn free_string_array(ptr: *mut *mut c_char, len: c_int) {
    let len = len as usize;

    // Get back our vector.
    // Previously we shrank to fit, so capacity == length.
    let v = Vec::from_raw_parts(ptr, len, len);

    // Now drop one string at a time.
    for elem in v {
        let s = CString::from_raw(elem);
        mem::drop(s);
    }

    // Afterwards the vector will be dropped and thus freed.
}
