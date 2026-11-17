#![no_main]

use libfuzzer_sys::fuzz_target;
use netscope::protocol::tls::parse_client_hello_sni;

fuzz_target!(|payload: &[u8]| {
    let hello = parse_client_hello_sni(payload);
    let Some(length) = payload.get(3..5) else {
        assert!(hello.is_none());
        return;
    };
    let record_end = 5 + usize::from(u16::from_be_bytes([length[0], length[1]]));
    let Some(record) = payload.get(..record_end) else {
        assert!(hello.is_none());
        return;
    };

    // Bytes beyond the declared record must not change the parse result.
    assert_eq!(parse_client_hello_sni(record), hello);
    if hello.is_some() {
        assert!(parse_client_hello_sni(&record[..record_end - 1]).is_none());
    }
});
