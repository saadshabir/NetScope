#![no_main]

use libfuzzer_sys::fuzz_target;
use netscope::protocol::dns::DnsMessage;

fuzz_target!(|message: &[u8]| {
    let Ok(dns) = DnsMessage::parse(message) else {
        return;
    };
    let Ok(sections) = dns.parse_sections(usize::MAX, usize::MAX, usize::MAX, usize::MAX) else {
        return;
    };
    for question in sections.questions {
        // Section parsing has already validated the name's wire encoding.
        question
            .name()
            .expect("validated question name must decode");
    }
    for record in sections
        .answers
        .into_iter()
        .chain(sections.authorities)
        .chain(sections.additionals)
    {
        record.name().expect("validated owner name must decode");
        // Name-bearing RDATA can contain its own compression pointers.
        let _ = record.rdata_display();
    }
});
