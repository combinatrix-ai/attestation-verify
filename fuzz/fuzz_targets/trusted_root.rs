#![no_main]

//! Fuzz the public trusted-root parser, including RFC 3339 validity windows.

use attestation_verify::TrustStore;
use libfuzzer_sys::fuzz_target;

fn parse(data: &[u8]) -> Result<(), attestation_verify::Error> {
    TrustStore::from_json(data).map(|_| ())
}

fuzz_target!(|data: &[u8]| {
    let _result = parse(data);
});
