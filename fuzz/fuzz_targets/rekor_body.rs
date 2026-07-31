#![no_main]

//! Fuzz Rekor's decoded canonicalized-body parser.

use attestation_verify::fuzzing::parse_rekor_canonicalized_body;
use libfuzzer_sys::fuzz_target;

fn parse(data: &[u8]) -> Result<(), attestation_verify::Error> {
    parse_rekor_canonicalized_body(data)
}

fuzz_target!(|data: &[u8]| {
    let _result = parse(data);
});
