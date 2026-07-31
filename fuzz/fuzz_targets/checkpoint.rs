#![no_main]

//! Fuzz Rekor's signed-note/checkpoint envelope parser.

use attestation_verify::fuzzing::parse_checkpoint;
use libfuzzer_sys::fuzz_target;

fn parse(data: &[u8]) -> Result<(), attestation_verify::Error> {
    let text = String::from_utf8_lossy(data);
    parse_checkpoint(&text)
}

fuzz_target!(|data: &[u8]| {
    let _result = parse(data);
});
