#![no_main]

//! Fuzz the hand-rolled RFC 3339 timestamp parser.

use attestation_verify::fuzzing::parse_rfc3339;
use libfuzzer_sys::fuzz_target;

fn parse(data: &[u8]) -> Result<(), attestation_verify::Error> {
    let text = String::from_utf8_lossy(data);
    parse_rfc3339(&text).map(|_| ())
}

fuzz_target!(|data: &[u8]| {
    let _result = parse(data);
});
