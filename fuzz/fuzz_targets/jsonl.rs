#![no_main]

//! Fuzz the public JSONL bundle-container parser.

use attestation_verify::BundleSet;
use libfuzzer_sys::fuzz_target;

fn parse(data: &[u8]) -> Result<(), attestation_verify::Error> {
    BundleSet::from_json_lines(data).map(|_| ())
}

fuzz_target!(|data: &[u8]| {
    let _result = parse(data);
});
