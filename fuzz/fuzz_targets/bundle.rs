#![no_main]

//! Fuzz the public Sigstore bundle parser.

use attestation_verify::Bundle;
use libfuzzer_sys::fuzz_target;

fn parse(data: &[u8]) -> Result<(), attestation_verify::Error> {
    Bundle::from_json(data).map(|_| ())
}

fuzz_target!(|data: &[u8]| {
    let _result = parse(data);
});
