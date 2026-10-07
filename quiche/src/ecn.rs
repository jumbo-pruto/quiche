// Copyright (C) 2026, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

//! Sender-side ECN validation, per
//! <https://www.rfc-editor.org/rfc/rfc9000#section-13.4.2> and the sample
//! algorithm in Appendix A.4.
//!
//! This is intentionally simplified for a single validated path: the number
//! of ECT(0) packets sent while probing is bounded purely by count (not also
//! by a PTO-based time budget), and there is no automatic re-probing after a
//! path enters the `Failed` state.

use crate::EcnCodepoint;

/// Maximum number of packets to mark while probing a path for ECN support,
/// per RFC 9000 Appendix A.4.
const ECN_TESTING_PACKET_BUDGET: u64 = 10;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    /// Actively probing the path by marking packets ECT(0).
    Testing,

    /// The probing budget was exhausted without conclusive feedback yet;
    /// packets are sent unmarked while awaiting validation of the packets
    /// already sent during `Testing`.
    Unknown,

    /// Validation succeeded; packets continue to be marked ECT(0).
    Capable,

    /// Validation failed; packets are sent unmarked for the rest of the
    /// path's lifetime.
    Failed,
}

/// Sender-side ECN validation state for a single network path.
#[derive(Clone, Copy, Debug)]
pub(crate) struct EcnSender {
    state: State,

    /// Packets marked ECT(0) so far while in the `Testing` state.
    testing_sent: u64,

    /// Cumulative count of packets this endpoint has sent on this path with
    /// the ECT(0) codepoint.
    sent_ect0: u64,

    /// Peer-reported cumulative ECT(0) count as of the last packet for which
    /// validation was attempted.
    acked_ect0: u64,

    /// Peer-reported cumulative CE count as of the last packet for which
    /// validation was attempted.
    acked_ce: u64,
}

impl EcnSender {
    pub(crate) fn new() -> Self {
        EcnSender {
            state: State::Testing,
            testing_sent: 0,
            sent_ect0: 0,
            acked_ect0: 0,
            acked_ce: 0,
        }
    }

    /// Returns the codepoint that would be used for the next outgoing
    /// datagram on this path, without consuming any of the testing budget.
    ///
    /// Use this to decide what to put on the wire; call [`Self::commit_sent`]
    /// only once a datagram using that codepoint is definitely being sent,
    /// since the latter mutates the testing budget.
    pub(crate) fn current_codepoint(&self) -> EcnCodepoint {
        match self.state {
            State::Testing | State::Capable => EcnCodepoint::Ect0,
            State::Unknown | State::Failed => EcnCodepoint::NotEct,
        }
    }

    /// Records that a datagram was actually sent using the codepoint
    /// returned by the most recent [`Self::current_codepoint`] call, and
    /// updates internal accounting accordingly.
    pub(crate) fn commit_sent(&mut self) {
        match self.state {
            State::Testing => {
                self.testing_sent += 1;
                self.sent_ect0 += 1;

                if self.testing_sent >= ECN_TESTING_PACKET_BUDGET {
                    self.state = State::Unknown;
                }
            },

            State::Capable => self.sent_ect0 += 1,

            State::Unknown | State::Failed => (),
        }
    }

    /// Convenience helper combining [`Self::current_codepoint`] and
    /// [`Self::commit_sent`], for callers that know a packet using the
    /// returned codepoint will unconditionally be sent.
    #[cfg(test)]
    pub(crate) fn next_codepoint(&mut self) -> EcnCodepoint {
        let codepoint = self.current_codepoint();
        self.commit_sent();
        codepoint
    }

    /// Validates the cumulative ECN counts carried by a newly processed ACK
    /// frame, per RFC 9000 Section 13.4.2.1, updates sender state
    /// accordingly, and returns whether the caller should apply a
    /// congestion response for a validated CE mark.
    ///
    /// `peer_counts` must be `None` when the ACK frame carried no ECN
    /// counts at all, and `Some((ect0, ce))` otherwise. `newly_acked_ect0`
    /// is the number of packets newly acknowledged by this ACK that this
    /// endpoint had sent with the ECT(0) codepoint.
    ///
    /// The returned value is `true` only when validation succeeded on this
    /// call AND the peer's reported CE count increased, i.e. there is a
    /// genuine new CE mark to respond to; it is `false` for a purely
    /// ECT(0)-evidenced validation, a no-op call, or a failure.
    pub(crate) fn validate(
        &mut self, peer_counts: Option<(u64, u64)>, newly_acked_ect0: u64,
    ) -> bool {
        if self.state == State::Failed || newly_acked_ect0 == 0 {
            return false;
        }

        let Some((peer_ect0, peer_ce)) = peer_counts else {
            // A newly acknowledged marked packet with no ECN counts at all
            // fails validation immediately.
            self.state = State::Failed;
            return false;
        };

        // Reported counts must not exceed what was actually sent, and must
        // not have decreased since the last validated ACK.
        if peer_ect0 > self.sent_ect0 ||
            peer_ect0 < self.acked_ect0 ||
            peer_ce < self.acked_ce
        {
            self.state = State::Failed;
            return false;
        }

        let delta_ect0 = peer_ect0 - self.acked_ect0;
        let delta_ce = peer_ce - self.acked_ce;

        // The combined increase in ECT(0) and CE counts must cover every
        // newly acknowledged marked packet.
        if delta_ect0 + delta_ce < newly_acked_ect0 {
            self.state = State::Failed;
            return false;
        }

        self.acked_ect0 = peer_ect0;
        self.acked_ce = peer_ce;

        if matches!(self.state, State::Testing | State::Unknown) {
            self.state = State::Capable;
        }

        delta_ce > 0
    }

    #[cfg(test)]
    pub(crate) fn is_capable(&self) -> bool {
        self.state == State::Capable
    }

    #[cfg(test)]
    pub(crate) fn is_testing(&self) -> bool {
        self.state == State::Testing
    }

    #[cfg(test)]
    pub(crate) fn is_unknown(&self) -> bool {
        self.state == State::Unknown
    }

    #[cfg(test)]
    pub(crate) fn is_failed(&self) -> bool {
        self.state == State::Failed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marks_ect0_while_testing() {
        let mut sender = EcnSender::new();

        for _ in 0..ECN_TESTING_PACKET_BUDGET {
            assert!(sender.is_testing());
            assert_eq!(sender.next_codepoint(), EcnCodepoint::Ect0);
        }

        // The budget is now exhausted.
        assert!(sender.is_unknown());
        assert_eq!(sender.next_codepoint(), EcnCodepoint::NotEct);
    }

    #[test]
    fn successful_validation_becomes_capable() {
        let mut sender = EcnSender::new();

        assert_eq!(sender.next_codepoint(), EcnCodepoint::Ect0);

        assert!(!sender.validate(Some((1, 0)), 1));

        assert!(sender.is_capable());
        assert_eq!(sender.next_codepoint(), EcnCodepoint::Ect0);
    }

    #[test]
    fn validation_succeeds_via_ce_evidence() {
        let mut sender = EcnSender::new();

        assert_eq!(sender.next_codepoint(), EcnCodepoint::Ect0);

        // The single marked packet was reported back as CE, not ECT(0); this
        // still counts as valid evidence that the path carries ECN, and
        // warrants a congestion response.
        assert!(sender.validate(Some((0, 1)), 1));

        assert!(sender.is_capable());
    }

    #[test]
    fn missing_ecn_counts_fails_validation() {
        let mut sender = EcnSender::new();

        assert_eq!(sender.next_codepoint(), EcnCodepoint::Ect0);

        assert!(!sender.validate(None, 1));

        assert!(sender.is_failed());
        assert_eq!(sender.next_codepoint(), EcnCodepoint::NotEct);
    }

    #[test]
    fn bleaching_fails_validation() {
        let mut sender = EcnSender::new();

        assert_eq!(sender.next_codepoint(), EcnCodepoint::Ect0);

        // Reported counts never increase, even though a marked packet was
        // newly acknowledged: the marking was stripped in the network.
        assert!(!sender.validate(Some((0, 0)), 1));

        assert!(sender.is_failed());
    }

    #[test]
    fn excess_reported_count_fails_validation() {
        let mut sender = EcnSender::new();

        assert_eq!(sender.next_codepoint(), EcnCodepoint::Ect0);

        // Only one ECT(0) packet was ever sent, so a reported count of 5 is
        // impossible and indicates remarking in the network.
        assert!(!sender.validate(Some((5, 0)), 1));

        assert!(sender.is_failed());
    }

    #[test]
    fn decreasing_reported_count_fails_validation() {
        let mut sender = EcnSender::new();

        sender.next_codepoint();
        sender.next_codepoint();
        assert!(!sender.validate(Some((2, 0)), 2));
        assert!(sender.is_capable());

        sender.next_codepoint();
        // A later ACK reports fewer ECT(0) packets than were already
        // validated; this is treated as inconsistent feedback.
        assert!(!sender.validate(Some((1, 0)), 1));

        assert!(sender.is_failed());
    }

    #[test]
    fn no_newly_marked_packets_does_not_validate_or_fail() {
        let mut sender = EcnSender::new();

        // No packets have been sent yet, so there is nothing to validate.
        assert!(!sender.validate(Some((0, 0)), 0));

        assert!(sender.is_testing());
    }

    #[test]
    fn subsequent_ce_increase_while_capable_triggers_response() {
        let mut sender = EcnSender::new();

        sender.next_codepoint();
        assert!(!sender.validate(Some((1, 0)), 1));
        assert!(sender.is_capable());

        sender.next_codepoint();
        // A later CE mark on an already-validated path still warrants a
        // congestion response.
        assert!(sender.validate(Some((1, 1)), 1));
        assert!(sender.is_capable());
    }

    #[test]
    fn failed_state_is_permanent_for_this_slice() {
        let mut sender = EcnSender::new();

        sender.next_codepoint();
        assert!(!sender.validate(None, 1));
        assert!(sender.is_failed());

        // Even conclusive-looking evidence afterwards does not reopen
        // validation; there is no automatic retry in this implementation.
        assert!(!sender.validate(Some((100, 100)), 1));
        assert!(sender.is_failed());
    }
}
