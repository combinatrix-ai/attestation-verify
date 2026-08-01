#![no_main]

//! Fuzz Rekor's signed-note/checkpoint *verification*, not just its parser.
//!
//! The sibling `checkpoint` target stops at `parse_checkpoint`. Everything
//! whose cost is chosen by the input — the key-hint filter, the
//! `MAX_CHECKPOINT_SIGNATURES` bound, and the ECDSA loop — runs after that
//! point, so only this target puts it under libFuzzer's time and memory
//! budgets.

use attestation_verify::fuzzing::verify_checkpoint;
use libfuzzer_sys::fuzz_target;

fn verify(data: &[u8]) -> Result<(), attestation_verify::Error> {
    let text = String::from_utf8_lossy(data);
    verify_checkpoint(&text)
}

fuzz_target!(|data: &[u8]| {
    let _result = verify(data);
});
