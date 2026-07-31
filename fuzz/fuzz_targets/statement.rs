#![no_main]

//! Fuzz in-toto statement parsing through the public bundle entry point.

use attestation_verify::Bundle;
use libfuzzer_sys::fuzz_target;

fn parse(data: &[u8]) -> Result<(), attestation_verify::Error> {
    Bundle::from_json(data)
        .and_then(|bundle| bundle.statement())
        .map(|_| ())
}

fuzz_target!(|data: &[u8]| {
    let _result = parse(data);
});
