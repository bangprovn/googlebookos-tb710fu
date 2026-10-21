//! Tests the exact inherited-descriptor handshake compiled by the private VMM.
#[path = "../../../patches/tb710fu/crosvm/prepin_pipe.rs"]
mod prepin_pipe;
fn main() {
    let _ = prepin_pipe::coordinate::<fn(&str)>;
}
