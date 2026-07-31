#![no_main]

//! Fuzz the TLS-encoded RFC 6962 SCT-list parser.

use attestation_verify::fuzzing::parse_sct_list;
use libfuzzer_sys::fuzz_target;

fn parse(data: &[u8]) -> Result<(), attestation_verify::Error> {
    parse_sct_list(data)
}

fuzz_target!(|data: &[u8]| {
    let _result = parse(data);
});
