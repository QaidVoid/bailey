//! The HTTP codec fuzz target: the request codec in both target forms, and
//! the response state machine, driven the way a broker connection drives
//! them. A refusal is an ordinary outcome. The invariant is that nothing
//! panics and nothing loops.

#![no_main]

use bailey_broker::request::{self, Form};
use bailey_broker::response::{self};

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The request codec: read and parse in both target forms, then relay
    // the body under the framing the head declares.
    let mut reader = data;
    if let Ok(head) = request::read_request(&mut reader, Form::Origin) {
        let _ = request::relay_body(&mut &data[..], &mut Vec::new(), head.body);
        let _ = head.check_host("fuzz.test", 443, 443);
        let _ = head.serialise("fuzz.test", 443, 443);
    }
    let mut reader = data;
    if let Ok(head) = request::read_request(&mut reader, Form::Absolute) {
        let _ = request::relay_body(&mut &data[..], &mut Vec::new(), head.body);
        if let Some((host, port)) = &head.authority {
            let _ = head.check_host(host, *port, 80);
            let _ = head.serialise(host, *port, 80);
        }
    }

    // The response codec: the steps of one exchange, then the body relay
    // under the framing the final step declares.
    let mut reader = data;
    if let Ok(response::Step::Final(head)) = response::read_step(&mut reader, "GET") {
        let _ = response::relay_body(&mut &data[..], &mut Vec::new(), head.body);
        let _ = head.serialise();
    }
});
