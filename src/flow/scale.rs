use super::{FlowDirection, FlowProtocol, TcpFlags, TcpState, update_tcp_state_fields};

#[derive(Debug, Clone)]
#[repr(C)]
pub(crate) struct ScaleFlowEntry {
    pub(crate) bytes_a_to_b: u64,
    pub(crate) bytes_b_to_a: u64,
    stats_report_total: u64,
    web_report_total: u64,
    first_seen_ts: f64,
    last_seen_ts: f64,
    pub(crate) packets_a_to_b: u32,
    pub(crate) packets_b_to_a: u32,
    fin_seen: u8,
    tcp_state: u8,
    client: u8,
    _pad: [u8; 5],
}

const SCALE_TCP_STATE_NONE: u8 = 7;

impl ScaleFlowEntry {
    pub(crate) fn new(ts: f64, protocol: FlowProtocol) -> Self {
        let tcp_state = match protocol {
            FlowProtocol::Tcp => Some(TcpState::Unknown),
            FlowProtocol::Udp => None,
        };
        ScaleFlowEntry {
            bytes_a_to_b: 0,
            bytes_b_to_a: 0,
            stats_report_total: 0,
            web_report_total: 0,
            first_seen_ts: ts,
            last_seen_ts: ts,
            packets_a_to_b: 0,
            packets_b_to_a: 0,
            fin_seen: 0,
            tcp_state: Self::encode_tcp_state(tcp_state),
            client: Self::encode_client(None),
            _pad: [0; 5],
        }
    }

    #[inline]
    pub(crate) fn observe(
        &mut self,
        ts: f64,
        direction: FlowDirection,
        bytes: u64,
        flags: Option<TcpFlags>,
    ) {
        self.first_seen_ts = self.first_seen_ts.min(ts);
        self.last_seen_ts = self.last_seen_ts.max(ts);
        match direction {
            FlowDirection::AtoB => {
                self.packets_a_to_b = self.packets_a_to_b.saturating_add(1);
                self.bytes_a_to_b = self.bytes_a_to_b.saturating_add(bytes);
            }
            FlowDirection::BtoA => {
                self.packets_b_to_a = self.packets_b_to_a.saturating_add(1);
                self.bytes_b_to_a = self.bytes_b_to_a.saturating_add(bytes);
            }
        }
        if let Some(flags) = flags {
            let mut tcp_state = self.tcp_state();
            let mut client = self.client();
            update_tcp_state_fields(
                &mut tcp_state,
                &mut client,
                &mut self.fin_seen,
                flags,
                direction,
            );
            self.set_tcp_state(tcp_state);
            self.set_client(client);
        }
    }

    #[inline]
    pub(crate) fn total_bytes(&self) -> u64 {
        self.bytes_a_to_b + self.bytes_b_to_a
    }

    #[inline]
    pub(crate) fn total_packets(&self) -> u64 {
        self.packets_a_to_b as u64 + self.packets_b_to_a as u64
    }

    #[inline]
    pub(crate) fn stats_delta(&self) -> u64 {
        self.total_bytes().saturating_sub(self.stats_report_total)
    }

    #[inline]
    pub(crate) fn web_delta(&self) -> u64 {
        self.total_bytes().saturating_sub(self.web_report_total)
    }

    #[inline]
    pub(crate) fn mark_stats_reported(&mut self) {
        self.stats_report_total = self.total_bytes();
    }

    #[inline]
    pub(crate) fn mark_web_reported(&mut self) {
        self.web_report_total = self.total_bytes();
    }

    #[inline]
    pub(crate) fn first_seen(&self) -> f64 {
        self.first_seen_ts
    }

    #[inline]
    pub(crate) fn last_seen(&self) -> f64 {
        self.last_seen_ts
    }

    #[inline]
    pub(crate) fn tcp_state(&self) -> Option<TcpState> {
        Self::decode_tcp_state(self.tcp_state)
    }

    #[inline]
    fn set_tcp_state(&mut self, state: Option<TcpState>) {
        self.tcp_state = Self::encode_tcp_state(state);
    }

    #[inline]
    pub(crate) fn client(&self) -> Option<FlowDirection> {
        Self::decode_client(self.client)
    }

    #[inline]
    fn set_client(&mut self, client: Option<FlowDirection>) {
        self.client = Self::encode_client(client);
    }

    #[inline]
    fn encode_tcp_state(state: Option<TcpState>) -> u8 {
        match state {
            Some(TcpState::SynSent) => 0,
            Some(TcpState::SynAck) => 1,
            Some(TcpState::Established) => 2,
            Some(TcpState::FinWait) => 3,
            Some(TcpState::Closed) => 4,
            Some(TcpState::Reset) => 5,
            Some(TcpState::Unknown) => 6,
            None => SCALE_TCP_STATE_NONE,
        }
    }

    #[inline]
    fn decode_tcp_state(code: u8) -> Option<TcpState> {
        match code {
            0 => Some(TcpState::SynSent),
            1 => Some(TcpState::SynAck),
            2 => Some(TcpState::Established),
            3 => Some(TcpState::FinWait),
            4 => Some(TcpState::Closed),
            5 => Some(TcpState::Reset),
            6 => Some(TcpState::Unknown),
            _ => None,
        }
    }

    #[inline]
    fn encode_client(client: Option<FlowDirection>) -> u8 {
        match client {
            Some(FlowDirection::AtoB) => 1,
            Some(FlowDirection::BtoA) => 2,
            None => 0,
        }
    }

    #[inline]
    fn decode_client(code: u8) -> Option<FlowDirection> {
        match code {
            1 => Some(FlowDirection::AtoB),
            2 => Some(FlowDirection::BtoA),
            _ => None,
        }
    }
}
