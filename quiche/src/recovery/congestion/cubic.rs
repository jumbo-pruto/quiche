// Copyright (C) 2019, Cloudflare, Inc.
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

//! CUBIC Congestion Control
//!
//! This implementation is based on the following draft:
//! <https://tools.ietf.org/html/draft-ietf-tcpm-rfc8312bis-02>
//!
//! Note that Slow Start can use HyStart++ when enabled.

use std::cmp;

use std::time::Duration;
use std::time::Instant;

use super::rtt::RttStats;
use super::Acked;
use super::Sent;

use super::reno;
use super::Congestion;
use super::CongestionControlOps;
use crate::recovery::MINIMUM_WINDOW_PACKETS;

pub(crate) static CUBIC: CongestionControlOps = CongestionControlOps {
    on_init,
    on_packet_sent,
    on_packets_acked,
    congestion_event,
    checkpoint,
    rollback,
    #[cfg(feature = "qlog")]
    state_str,
    debug_fmt,
};

/// CUBIC Constants.
///
/// These are recommended value in RFC8312.
const BETA_CUBIC: f64 = 0.7;

const C: f64 = 0.4;

/// Threshold for rolling back state, as percentage of lost packets relative to
/// cwnd.
const ROLLBACK_THRESHOLD_PERCENT: usize = 20;

/// Minimum threshold for rolling back state, as number of packets.
const MIN_ROLLBACK_THRESHOLD: usize = 2;

/// Default value of alpha_aimd in the beginning of congestion avoidance.
const ALPHA_AIMD: f64 = 3.0 * (1.0 - BETA_CUBIC) / (1.0 + BETA_CUBIC);

// EXPERIMENT KNOBS (testbed only, never commit). Read once from the env;
// all unset = stock quiche behaviour.
//   CUBIC_BETA=<f64>        multiplicative decrease (default 0.7)
//   CUBIC_NO_ROLLBACK=1     disable the 20%-of-cwnd spurious-loss rollback
//   CUBIC_WEST_HALF=1       after a cut, restart W_est at old_cwnd/2
//                           (picoquic: W_reno = cwin/2) instead of new cwnd
//   CUBIC_LOSS_FILTER=1     picoquic smoothed-loss filter: only start a new
//                           congestion event once the EWMA drop rate over
//                           packet numbers (factor 1/16) exceeds 0.15
struct Knobs {
    beta: f64,
    no_rollback: bool,
    west_half: bool,
    loss_filter: bool,
    pico_fc: bool,
    no_fc: bool,
    srtt: bool,
}

fn knobs() -> &'static Knobs {
    static K: std::sync::OnceLock<Knobs> = std::sync::OnceLock::new();
    K.get_or_init(|| {
        let on = |k: &str| std::env::var(k).map(|v| v == "1").unwrap_or(false);
        let k = Knobs {
            beta: std::env::var("CUBIC_BETA")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(BETA_CUBIC),
            no_rollback: on("CUBIC_NO_ROLLBACK"),
            west_half: on("CUBIC_WEST_HALF"),
            loss_filter: on("CUBIC_LOSS_FILTER"),
            pico_fc: on("CUBIC_PICO_FC"),
            no_fc: on("CUBIC_NO_FC"),
            srtt: on("CUBIC_SRTT"),
        };
        eprintln!(
            "KNOBS beta={} no_rollback={} west_half={} loss_filter={} pico_fc={} no_fc={} srtt={}",
            k.beta, k.no_rollback, k.west_half, k.loss_filter, k.pico_fc,
            k.no_fc, k.srtt
        );
        k
    })
}

fn beta() -> f64 {
    knobs().beta
}

fn alpha_aimd() -> f64 {
    3.0 * (1.0 - beta()) / (1.0 + beta())
}

/// CUBIC State Variables.
///
/// We need to keep those variables across the connection.
/// k, w_max, w_est are described in the RFC.
#[derive(Debug, Default)]
pub struct State {
    k: f64,

    w_max: f64,

    w_est: f64,

    alpha_aimd: f64,

    // Used in CUBIC fix (see on_packet_sent())
    last_sent_time: Option<Instant>,

    // Tracks when the last ACK was processed, approximating when
    // bytes_in_flight transitioned toward zero. Used to measure the
    // actual idle duration in on_packet_sent() instead of the time
    // since the last send (which inflates the delta by a full RTT).
    last_ack_time: Option<Instant>,

    // Store cwnd increment during congestion avoidance.
    cwnd_inc: usize,

    // CUBIC_LOSS_FILTER state (picoquic cc_common.c hystart_loss_test).
    smoothed_drop_rate: f64,
    last_lost_pn: u64,

    // CUBIC_PICO_FC state (picoquic W_last_max).
    w_last_max: f64,

    // CUBIC state checkpoint preceding the last congestion event.
    prior: PriorState,
}

/// Stores the CUBIC state from before the last congestion event.
///
/// <https://tools.ietf.org/id/draft-ietf-tcpm-rfc8312bis-00.html#section-4.9>
#[derive(Debug, Default)]
struct PriorState {
    congestion_window: usize,

    ssthresh: usize,

    w_max: f64,

    k: f64,

    epoch_start: Option<Instant>,

    lost_count: usize,
}

/// CUBIC Functions.
///
/// Note that these calculations are based on a count of cwnd as bytes,
/// not packets.
/// Unit of t (duration) and RTT are based on seconds (f64).
impl State {
    // K = cubic_root ((w_max - cwnd) / C) (Eq. 2)
    fn cubic_k(&self, cwnd: usize, max_datagram_size: usize) -> f64 {
        let w_max = self.w_max / max_datagram_size as f64;
        let cwnd = cwnd as f64 / max_datagram_size as f64;

        libm::cbrt((w_max - cwnd) / C)
    }

    // W_cubic(t) = C * (t - K)^3 + w_max (Eq. 1)
    fn w_cubic(&self, t: Duration, max_datagram_size: usize) -> f64 {
        let w_max = self.w_max / max_datagram_size as f64;

        (C * (t.as_secs_f64() - self.k).powi(3) + w_max) *
            max_datagram_size as f64
    }

    // W_est = W_est + alpha_aimd * (segments_acked / cwnd)  (Eq. 4)
    fn w_est_inc(
        &self, acked: usize, cwnd: usize, max_datagram_size: usize,
    ) -> f64 {
        self.alpha_aimd * (acked as f64 / cwnd as f64) * max_datagram_size as f64
    }
}

fn on_init(_r: &mut Congestion) {}

fn on_packet_sent(
    r: &mut Congestion, sent_bytes: usize, bytes_in_flight: usize, now: Instant,
) {
    reno::on_packet_sent(r, sent_bytes, bytes_in_flight, now);

    // Don't adjust epoch or track send time for non-data packets
    // (e.g. ACKs). These have in_flight=true but size=0.
    // Skip all the following logic for these packets.
    if sent_bytes == 0 && r.enable_cubic_idle_restart_fix {
        return;
    }

    // See https://github.com/torvalds/linux/commit/30927520dbae297182990bb21d08762bcc35ce1d
    // First transmit when no packets in flight.
    // Shift epoch start to keep cwnd growth on the cubic curve.
    let cubic = &mut r.cubic_state;

    if bytes_in_flight == 0 {
        if let Some(recovery_start_time) = r.congestion_recovery_start_time {
            // Measure idle from the most recent activity: either the
            // last ACK (approximating when bif hit 0) or the last data
            // send, whichever is later. Using last_sent_time alone
            // would inflate the delta by a full RTT when cwnd is small
            // and bif transiently hits 0 between ACK and send.
            let idle_start = if r.enable_cubic_idle_restart_fix {
                cmp::max(cubic.last_ack_time, cubic.last_sent_time)
            } else {
                cubic.last_sent_time
            };

            if let Some(idle_start) = idle_start {
                if idle_start < now {
                    let delta = now - idle_start;
                    r.congestion_recovery_start_time =
                        Some(recovery_start_time + delta);
                }
            }
        }
    }

    cubic.last_sent_time = Some(now);
}

fn on_packets_acked(
    r: &mut Congestion, bytes_in_flight: usize, packets: &mut Vec<Acked>,
    now: Instant, rtt_stats: &RttStats,
) {
    r.cubic_state.last_ack_time = Some(now);

    for pkt in packets.drain(..) {
        on_packet_acked(r, bytes_in_flight, &pkt, now, rtt_stats);
    }
}

fn on_packet_acked(
    r: &mut Congestion, bytes_in_flight: usize, packet: &Acked, now: Instant,
    rtt_stats: &RttStats,
) {
    let in_congestion_recovery = r.in_congestion_recovery(packet.time_sent);

    if in_congestion_recovery {
        r.prr.on_packet_acked(
            packet.size,
            bytes_in_flight,
            r.ssthresh.get(),
            r.max_datagram_size,
        );

        return;
    }

    if r.app_limited {
        return;
    }

    // Detecting spurious congestion events.
    // <https://tools.ietf.org/id/draft-ietf-tcpm-rfc8312bis-00.html#section-4.9>
    //
    // If recovery ends after fewer than
    // `cwnd / mss * ROLLBACK_THRESHOLD_PERCENT` packets, treat the congestion
    // event as spurious and restore the previous state.
    if r.congestion_recovery_start_time.is_some() {
        let new_lost = r.lost_count - r.cubic_state.prior.lost_count;

        let rollback_threshold = (r.congestion_window / r.max_datagram_size) *
            ROLLBACK_THRESHOLD_PERCENT /
            100;

        let rollback_threshold = rollback_threshold.max(MIN_ROLLBACK_THRESHOLD);

        if !knobs().no_rollback && new_lost < rollback_threshold {
            let dbg_from = r.congestion_window / r.max_datagram_size;
            let did_rollback = rollback(r);
            if did_rollback {
                eprintln!(
                    "ROLLBACKDBG epoch={:.6} cwnd_from={} cwnd_to={} new_lost={} thresh={}",
                    dbg_epoch(),
                    dbg_from,
                    r.congestion_window / r.max_datagram_size,
                    new_lost,
                    rollback_threshold
                );
                return;
            }
        }
    }

    if r.congestion_window < r.ssthresh.get() {
        // In Slow start, bytes_acked_sl is used for counting
        // acknowledged bytes.
        r.bytes_acked_sl += packet.size;

        if r.bytes_acked_sl >= r.max_datagram_size {
            if r.hystart.in_css() {
                r.congestion_window +=
                    r.hystart.css_cwnd_inc(r.max_datagram_size);
            } else {
                r.congestion_window += r.max_datagram_size;
            }

            r.bytes_acked_sl -= r.max_datagram_size;
        }

        if r.hystart.on_packet_acked(packet, rtt_stats.latest_rtt, now) {
            // Exit to congestion avoidance if CSS ends.
            r.ssthresh.update(r.congestion_window, true);
        }
    } else {
        // Congestion avoidance.
        let ca_start_time;

        // In CSS, use css_start_time instead of congestion_recovery_start_time.
        if r.hystart.in_css() {
            ca_start_time = r.hystart.css_start_time().unwrap();

            // Reset w_max and k when CSS started.
            if r.cubic_state.w_max == 0.0 {
                r.cubic_state.w_max = r.congestion_window as f64;
                r.cubic_state.k = 0.0;

                r.cubic_state.w_est = r.congestion_window as f64;
                r.cubic_state.alpha_aimd = alpha_aimd();
            }
        } else {
            match r.congestion_recovery_start_time {
                Some(t) => ca_start_time = t,
                None => {
                    // When we come here without congestion_event() triggered,
                    // initialize congestion_recovery_start_time, w_max and k.
                    ca_start_time = now;
                    r.congestion_recovery_start_time = Some(now);

                    r.cubic_state.w_max = r.congestion_window as f64;
                    r.cubic_state.k = 0.0;

                    r.cubic_state.w_est = r.congestion_window as f64;
                    r.cubic_state.alpha_aimd = alpha_aimd();
                },
            }
        }

        let t = now.saturating_duration_since(ca_start_time);

        // target = w_cubic(t + rtt)
        // CUBIC_SRTT=1: RFC 9438 sec 4.2 uses the smoothed RTT here; quiche
        // stock uses min_rtt.
        let lookahead = if knobs().srtt {
            rtt_stats.smoothed_rtt
        } else {
            *rtt_stats.min_rtt
        };
        let target = r.cubic_state.w_cubic(t + lookahead, r.max_datagram_size);

        // Clipping target to [cwnd, 1.5 x cwnd]
        let target = f64::max(target, r.congestion_window as f64);
        let target = f64::min(target, r.congestion_window as f64 * 1.5);

        // Update w_est.
        let w_est_inc = r.cubic_state.w_est_inc(
            packet.size,
            r.congestion_window,
            r.max_datagram_size,
        );
        r.cubic_state.w_est += w_est_inc;

        if r.cubic_state.w_est >= r.cubic_state.w_max {
            r.cubic_state.alpha_aimd = 1.0;
        }

        let mut cubic_cwnd = r.congestion_window;

        let dbg_wcubic = r.cubic_state.w_cubic(t, r.max_datagram_size);
        let dbg_aimd = dbg_wcubic < r.cubic_state.w_est;

        if r.cubic_state.w_cubic(t, r.max_datagram_size) < r.cubic_state.w_est {
            // AIMD friendly region (W_cubic(t) < W_est)
            cubic_cwnd = cmp::max(cubic_cwnd, r.cubic_state.w_est as usize);
        } else {
            // Concave region or convex region use same increment.
            let cubic_inc =
                r.max_datagram_size * (target as usize - cubic_cwnd) / cubic_cwnd;

            cubic_cwnd += cubic_inc;
        }

        // Update the increment and increase cwnd by MSS.
        r.cubic_state.cwnd_inc += cubic_cwnd - r.congestion_window;

        if r.cubic_state.cwnd_inc >= r.max_datagram_size {
            r.congestion_window += r.max_datagram_size;
            r.cubic_state.cwnd_inc -= r.max_datagram_size;
            let mds = r.max_datagram_size as f64;
            eprintln!(
                "CUBICDBG t={:.3} cwnd={} wcubic={:.1} west={:.1} wmax={:.1} target={:.1} region={}",
                t.as_secs_f64(),
                r.congestion_window / r.max_datagram_size,
                dbg_wcubic / mds,
                r.cubic_state.w_est / mds,
                r.cubic_state.w_max / mds,
                target / mds,
                if dbg_aimd { "AIMD" } else { "CUBIC" }
            );
        }
    }
}

// picoquic cc_common.c picoquic_cc_hystart_loss_test(), verbatim logic:
// EWMA of drops over packet numbers; true once the rate exceeds 0.15.
fn loss_filter_update(s: &mut State, lost_pn: u64) -> bool {
    const SCOPE: u64 = 32;
    const FACTOR: f64 = 1.0 / 16.0;
    const THRESH: f64 = 0.15;

    let mut next = s.last_lost_pn;
    if lost_pn <= next {
        return false;
    }
    if next + SCOPE < lost_pn {
        next = lost_pn - SCOPE;
    }
    while next < lost_pn {
        s.smoothed_drop_rate *= 1.0 - FACTOR;
        next += 1;
    }
    s.smoothed_drop_rate += (1.0 - s.smoothed_drop_rate) * FACTOR;
    s.last_lost_pn = lost_pn;
    s.smoothed_drop_rate > THRESH
}

fn congestion_event(
    r: &mut Congestion, bytes_in_flight: usize, lost_bytes: usize,
    largest_lost_pkt: &Sent, now: Instant,
) {
    let time_sent = largest_lost_pkt.time_sent;
    let in_congestion_recovery = r.in_congestion_recovery(time_sent);

    // CUBIC_LOSS_FILTER: like picoquic, only losses outside the current
    // recovery window feed the filter, and a new event needs it to pass.
    // quiche reports one batch per call, so feed its n packet numbers.
    if !in_congestion_recovery && knobs().loss_filter {
        let mds = r.max_datagram_size;
        let n = cmp::max(1, lost_bytes.div_ceil(mds)) as u64;
        let largest = largest_lost_pkt.pkt_num;
        let mut pass = false;
        for pn in largest.saturating_sub(n - 1)..=largest {
            pass = loss_filter_update(&mut r.cubic_state, pn);
        }
        if !pass {
            eprintln!(
                "FILTERDBG epoch={:.6} rate={:.3} skip",
                dbg_epoch(),
                r.cubic_state.smoothed_drop_rate
            );
            return;
        }
    }

    // Start a new congestion event if packet was sent after the
    // start of the previous congestion recovery period.
    if !in_congestion_recovery {
        let cwnd_before = r.congestion_window;
        let dbg_before = r.congestion_window / r.max_datagram_size;
        let dbg_age_ms = now.saturating_duration_since(time_sent).as_secs_f64() *
            1000.0;
        r.congestion_recovery_start_time = Some(now);

        // Fast convergence
        let ssthresh = if knobs().pico_fc {
            // picoquic cubic_enter_recovery(): W_max = cwnd; if below the
            // last W_max, W_max *= beta (and that lower W_max sets the cut);
            // new cwnd = ssthresh = beta * W_max.
            let w = r.congestion_window as f64;
            if w < r.cubic_state.w_last_max {
                r.cubic_state.w_last_max = w;
                r.cubic_state.w_max = w * beta();
            } else {
                r.cubic_state.w_last_max = w;
                r.cubic_state.w_max = w;
            }
            (r.cubic_state.w_max * beta()) as usize
        } else if knobs().no_fc {
            // CUBIC_NO_FC=1: RFC 9438 sec 4.7 -- with a single flow fast
            // convergence SHOULD be disabled: always remember cwnd.
            r.cubic_state.w_max = r.congestion_window as f64;
            (r.congestion_window as f64 * beta()) as usize
        } else {
            if (r.congestion_window as f64) < r.cubic_state.w_max {
                r.cubic_state.w_max =
                    r.congestion_window as f64 * (1.0 + beta()) / 2.0;
            } else {
                r.cubic_state.w_max = r.congestion_window as f64;
            }
            (r.congestion_window as f64 * beta()) as usize
        };
        let ssthresh =
            cmp::max(ssthresh, r.max_datagram_size * MINIMUM_WINDOW_PACKETS);
        r.ssthresh.update(ssthresh, r.hystart.in_css());
        r.congestion_window = ssthresh;

        r.cubic_state.k = if r.cubic_state.w_max < r.congestion_window as f64 {
            0.0
        } else {
            r.cubic_state
                .cubic_k(r.congestion_window, r.max_datagram_size)
        };

        r.cubic_state.cwnd_inc =
            (r.cubic_state.cwnd_inc as f64 * beta()) as usize;

        // CUBIC_WEST_HALF: picoquic restarts its Reno estimate at old_cwnd/2
        // (cubic.c cubic_enter_recovery), RFC 9438 at the new cwnd.
        r.cubic_state.w_est = if knobs().west_half {
            cwnd_before as f64 / 2.0
        } else {
            r.congestion_window as f64
        };
        r.cubic_state.alpha_aimd = alpha_aimd();

        if r.hystart.in_css() {
            r.hystart.congestion_event();
        }

        r.prr.congestion_event(bytes_in_flight);

        eprintln!(
            "CUTDBG epoch={:.6} cwnd_before={} cwnd_after={} wmax={:.1} inflight={} lost_age_ms={:.1}",
            dbg_epoch(),
            dbg_before,
            r.congestion_window / r.max_datagram_size,
            r.cubic_state.w_max / r.max_datagram_size as f64,
            bytes_in_flight / r.max_datagram_size,
            dbg_age_ms
        );
    }
}

fn dbg_epoch() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

fn checkpoint(r: &mut Congestion) {
    r.cubic_state.prior.congestion_window = r.congestion_window;
    r.cubic_state.prior.ssthresh = r.ssthresh.get();
    r.cubic_state.prior.w_max = r.cubic_state.w_max;
    r.cubic_state.prior.k = r.cubic_state.k;
    r.cubic_state.prior.epoch_start = r.congestion_recovery_start_time;
    r.cubic_state.prior.lost_count = r.lost_count;
}

fn rollback(r: &mut Congestion) -> bool {
    // Don't go back to slow start.
    if r.cubic_state.prior.congestion_window < r.cubic_state.prior.ssthresh {
        return false;
    }

    if r.congestion_window >= r.cubic_state.prior.congestion_window {
        return false;
    }

    r.congestion_window = r.cubic_state.prior.congestion_window;
    r.ssthresh.update(r.cubic_state.prior.ssthresh, false);
    r.cubic_state.w_max = r.cubic_state.prior.w_max;
    r.cubic_state.k = r.cubic_state.prior.k;
    r.congestion_recovery_start_time = r.cubic_state.prior.epoch_start;

    true
}

#[cfg(feature = "qlog")]
fn state_str(r: &Congestion, now: Instant) -> &'static str {
    reno::state_str(r, now)
}

fn debug_fmt(r: &Congestion, f: &mut std::fmt::Formatter) -> std::fmt::Result {
    write!(
        f,
        "cubic={{ k={} w_max={} }} ",
        r.cubic_state.k, r.cubic_state.w_max
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::CongestionControlAlgorithm;

    use crate::recovery::congestion::hystart;
    use crate::recovery::congestion::recovery::LegacyRecovery;
    use crate::recovery::congestion::test_sender::TestSender;
    use crate::recovery::RecoveryOps;

    fn test_sender() -> TestSender {
        TestSender::new(CongestionControlAlgorithm::CUBIC, false)
    }

    fn hystart_test_sender() -> TestSender {
        TestSender::new(CongestionControlAlgorithm::CUBIC, true)
    }

    #[test]
    fn cubic_init() {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(CongestionControlAlgorithm::CUBIC);

        let r = LegacyRecovery::new(&cfg);

        assert!(r.cwnd() > 0);
        assert_eq!(r.bytes_in_flight(), 0);
    }

    #[test]
    fn cubic_slow_start() {
        let mut sender = test_sender();
        let size = sender.max_datagram_size;

        // Send initcwnd full MSS packets to become no longer app limited
        for _ in 0..sender.initial_congestion_window_packets {
            sender.send_packet(size);
        }

        let cwnd_prev = sender.congestion_window;

        sender.ack_n_packets(1, size);

        // Check if cwnd increased by packet size (slow start)
        assert_eq!(sender.congestion_window, cwnd_prev + size);
    }

    #[test]
    fn cubic_slow_start_multi_acks() {
        let mut sender = test_sender();
        let size = sender.max_datagram_size;

        // Send initcwnd full MSS packets to become no longer app limited
        for _ in 0..sender.initial_congestion_window_packets {
            sender.send_packet(size);
        }

        let cwnd_prev = sender.congestion_window;

        sender.ack_n_packets(3, size);

        // Acked 3 packets.
        assert_eq!(sender.congestion_window, cwnd_prev + size * 3);
    }

    #[test]
    fn cubic_congestion_event() {
        let mut sender = test_sender();
        let size = sender.max_datagram_size;

        sender.send_packet(size);

        let cwnd_prev = sender.congestion_window;

        sender.lose_n_packets(1, size, None);

        // In CUBIC, after congestion event, cwnd will be reduced by (1 -
        // CUBIC_BETA)
        assert_eq!(
            cwnd_prev as f64 * BETA_CUBIC,
            sender.congestion_window as f64
        );
    }

    #[test]
    fn cubic_congestion_avoidance() {
        let mut sender = test_sender();
        let size = sender.max_datagram_size;

        let prev_cwnd = sender.congestion_window;

        // Send initcwnd full MSS packets to become no longer app limited
        for _ in 0..sender.initial_congestion_window_packets {
            sender.send_packet(size);
        }

        let rtt = Duration::from_millis(100);

        sender.advance_time(rtt);
        sender.lose_n_packets(1, size, None);

        // After congestion event, cwnd will be reduced.
        let cur_cwnd = (prev_cwnd as f64 * BETA_CUBIC) as usize;
        assert_eq!(sender.congestion_window, cur_cwnd);

        // Shift current time by 1 RTT.
        sender.update_rtt(rtt);
        // Exit from the recovery.
        sender.advance_time(rtt);

        sender.ack_n_packets(sender.initial_congestion_window_packets - 2, size);
        // Only packets sent after exit recovery can increase cwnd.
        assert_eq!(sender.congestion_window, cur_cwnd);

        for _ in 0..8 {
            sender.send_packet(size);
        }
        sender.advance_time(rtt);

        sender.ack_n_packets(1, size);
        // Only packets sent after exit recovery can increase cwnd.
        assert_eq!(sender.congestion_window, cur_cwnd);

        // During Congestion Avoidance, it will take
        // 6 ACKs to increase cwnd by 1 MSS.
        for _ in 0..6 {
            sender.ack_n_packets(1, size);
            sender.advance_time(rtt);
        }

        assert_eq!(sender.congestion_window, cur_cwnd + size);
    }

    #[test]
    fn cubic_hystart_css_to_ss() {
        let mut sender = hystart_test_sender();
        let size = sender.max_datagram_size;

        // 1st round.
        let n_rtt_sample = hystart::N_RTT_SAMPLE;

        let rtt_1st = Duration::from_millis(50);

        let next_rnd = sender.next_pkt + n_rtt_sample as u64 - 1;
        sender.hystart.start_round(next_rnd);
        // Send 1st round packets.
        for _ in 0..n_rtt_sample {
            sender.send_packet(size);
        }
        sender.update_app_limited(false);

        // Receiving Acks.
        sender.advance_time(rtt_1st);
        sender.update_rtt(rtt_1st);
        sender.ack_n_packets(n_rtt_sample, size);

        // Not in CSS yet.
        assert!(sender.hystart.css_start_time().is_none());

        // 2nd round.
        let mut rtt_2nd = Duration::from_millis(100);

        sender.advance_time(rtt_2nd);

        let next_rnd = sender.next_pkt + n_rtt_sample as u64 - 1;
        sender.hystart.start_round(next_rnd);
        // Send 2nd round packets.
        for _ in 0..n_rtt_sample {
            sender.send_packet(size);
        }
        sender.update_app_limited(false);

        // Receiving Acks.
        // Last ack will cause to exit to CSS.
        let mut cwnd_prev = sender.congestion_window();

        for _ in 0..n_rtt_sample {
            cwnd_prev = sender.congestion_window();
            sender.update_rtt(rtt_2nd);
            sender.ack_n_packets(1, size);
            // Keep increasing RTT so that hystart exits to CSS.
            rtt_2nd += rtt_2nd.saturating_add(Duration::from_millis(4));
        }

        // Now we are in CSS.
        assert!(sender.hystart.css_start_time().is_some());
        assert_eq!(sender.congestion_window(), cwnd_prev + size);

        // 3rd round, which RTT is less than previous round to
        // trigger back to Slow Start.
        let rtt_3rd = Duration::from_millis(80);
        sender.advance_time(rtt_3rd);
        cwnd_prev = sender.congestion_window();

        let next_rnd = sender.next_pkt + n_rtt_sample as u64 - 1;
        sender.hystart.start_round(next_rnd);
        // Send 3nd round packets.
        for _ in 0..n_rtt_sample {
            sender.send_packet(size);
        }
        sender.update_app_limited(false);

        // Receiving Acks.
        // Last ack will cause to exit to SS.
        sender.update_rtt(rtt_3rd);
        sender.ack_n_packets(n_rtt_sample, size);

        // Now we are back in Slow Start.
        assert!(sender.hystart.css_start_time().is_none());
        assert_eq!(
            sender.congestion_window(),
            cwnd_prev +
                size / hystart::CSS_GROWTH_DIVISOR * hystart::N_RTT_SAMPLE
        );
    }

    #[test]
    fn cubic_hystart_css_to_ca() {
        let mut sender = hystart_test_sender();
        let size = sender.max_datagram_size;

        // 1st round.
        let n_rtt_sample = hystart::N_RTT_SAMPLE;

        let rtt_1st = Duration::from_millis(50);

        let next_rnd = sender.next_pkt + n_rtt_sample as u64 - 1;
        sender.hystart.start_round(next_rnd);
        // Send 1st round packets.
        for _ in 0..n_rtt_sample {
            sender.send_packet(size);
        }
        sender.update_app_limited(false);

        // Receiving Acks.
        sender.advance_time(rtt_1st);
        sender.update_rtt(rtt_1st);
        sender.ack_n_packets(n_rtt_sample, size);

        // Not in CSS yet.
        assert!(sender.hystart.css_start_time().is_none());

        // 2nd round.
        let mut rtt_2nd = Duration::from_millis(100);
        sender.advance_time(rtt_2nd);
        // Send 2nd round packets.
        let next_rnd = sender.next_pkt + n_rtt_sample as u64 - 1;
        sender.hystart.start_round(next_rnd);
        for _ in 0..n_rtt_sample {
            sender.send_packet(size);
        }
        sender.update_app_limited(false);

        // Receiving Acks.
        // Last ack will cause to exit to CSS.
        let mut cwnd_prev = sender.congestion_window();

        for _ in 0..n_rtt_sample {
            cwnd_prev = sender.congestion_window();
            sender.update_rtt(rtt_2nd);
            sender.ack_n_packets(1, size);
            // Keep increasing RTT so that hystart exits to CSS.
            rtt_2nd += rtt_2nd.saturating_add(Duration::from_millis(4));
        }

        // Now we are in CSS.
        assert!(sender.hystart.css_start_time().is_some());
        assert_eq!(sender.congestion_window(), cwnd_prev + size);

        // Run 5 (CSS_ROUNDS) in CSS, to exit to congestion avoidance.
        let rtt_css = Duration::from_millis(100);
        sender.advance_time(rtt_css);

        for _ in 0..hystart::CSS_ROUNDS {
            // Send a round of packets.
            let next_rnd = sender.next_pkt + n_rtt_sample as u64 - 1;
            sender.hystart.start_round(next_rnd);
            for _ in 0..n_rtt_sample {
                sender.send_packet(size);
            }
            sender.update_app_limited(false);

            // Receiving Acks.
            sender.update_rtt(rtt_css);
            sender.ack_n_packets(n_rtt_sample, size);
        }
        // Now we are in congestion avoidance.
        assert_eq!(sender.congestion_window(), sender.ssthresh.get());
    }

    #[test]
    fn cubic_spurious_congestion_event() {
        let mut sender = test_sender();
        let size = sender.max_datagram_size;

        let prev_cwnd = sender.congestion_window();

        // Send initcwnd full MSS packets to become no longer app limited
        for _ in 0..sender.initial_congestion_window_packets {
            sender.send_packet(size);
        }
        sender.lose_n_packets(1, size, None);

        // After congestion event, cwnd will be reduced.
        let cur_cwnd = (prev_cwnd as f64 * BETA_CUBIC) as usize;
        assert_eq!(sender.congestion_window(), cur_cwnd);

        // Ack more than cwnd bytes with rtt=100ms
        let rtt = Duration::from_millis(100);
        sender.update_rtt(rtt);

        let acked = Acked {
            pkt_num: 0,
            // To exit from recovery
            time_sent: sender.time + rtt,
            size,
            delivered: 0,
            delivered_time: sender.time,
            first_sent_time: sender.time,
            is_app_limited: false,
            rtt: Duration::ZERO,
        };

        // Trigger detecting spurious congestion event
        sender.inject_ack(acked, sender.time + rtt + Duration::from_millis(5));

        // This is from slow start, no rollback.
        assert_eq!(sender.congestion_window(), cur_cwnd);

        sender.advance_time(rtt);

        let prev_cwnd = sender.congestion_window();

        sender.lose_n_packets(1, size, Some(sender.time));

        // After congestion event, cwnd will be reduced.
        let cur_cwnd = (cur_cwnd as f64 * BETA_CUBIC) as usize;
        assert_eq!(sender.congestion_window(), cur_cwnd);

        sender.advance_time(rtt + Duration::from_millis(5));

        let acked = Acked {
            pkt_num: 0,
            // To exit from recovery
            time_sent: sender.time + rtt,
            size,
            delivered: 0,
            delivered_time: sender.time,
            first_sent_time: sender.time,
            is_app_limited: false,
            rtt: Duration::ZERO,
        };

        // Trigger detecting spurious congestion event.
        sender.inject_ack(acked, sender.time + rtt + Duration::from_millis(5));

        // cwnd is rolled back to the previous one.
        assert_eq!(sender.congestion_window(), prev_cwnd);
    }

    #[test]
    fn cubic_fast_convergence() {
        let mut sender = test_sender();
        let size = sender.max_datagram_size;

        let prev_cwnd = sender.congestion_window;

        // Send initcwnd full MSS packets to become no longer app limited
        for _ in 0..sender.initial_congestion_window_packets {
            sender.send_packet(size);
        }

        // Trigger congestion event to update ssthresh
        sender.lose_n_packets(1, size, None);

        // After 1st congestion event, cwnd will be reduced.
        let cur_cwnd = (prev_cwnd as f64 * BETA_CUBIC) as usize;
        assert_eq!(sender.congestion_window, cur_cwnd);

        // Shift current time by 1 RTT.
        let rtt = Duration::from_millis(100);
        sender.update_rtt(rtt);
        // Exit from the recovery.
        sender.advance_time(rtt);

        // Drain most packets in flight except for 1 to avoid adjustments to
        // cubic.last_sent_time when idle, see on_packet_sent.
        sender.ack_n_packets(sender.initial_congestion_window_packets - 2, size);

        // During Congestion Avoidance, it will take 6 ACKs to
        // increase cwnd by 1 MSS.  But ACKed packets must have been
        // sent after the loss event.
        for _ in 0..7 {
            sender.send_packet(size);
        }
        // ACK the packet that was sent before the loss event.
        sender.ack_n_packets(1, size);
        sender.advance_time(rtt);
        for _ in 0..6 {
            sender.ack_n_packets(1, size);
        }

        assert_eq!(sender.congestion_window, cur_cwnd + size);

        let prev_cwnd = sender.congestion_window;

        // Fast convergence: now there is 2nd congestion event and
        // cwnd is not fully recovered to w_max, w_max will be
        // further reduced.
        sender.lose_n_packets(1, size, None);

        // After 2nd congestion event, cwnd will be reduced.
        let cur_cwnd = (prev_cwnd as f64 * BETA_CUBIC) as usize;
        assert_eq!(sender.congestion_window, cur_cwnd);

        // w_max will be further reduced, not prev_cwnd
        assert_eq!(
            sender.cubic_state.w_max,
            prev_cwnd as f64 * (1.0 + BETA_CUBIC) / 2.0
        );
    }

    #[test]
    fn cubic_perpetual_recovery_trap() {
        // Reproduces the bug where cwnd stays pinned at minimum after a
        // loss event because the idle-time epoch shift pushes
        // congestion_recovery_start_time into the future on every
        // send -> ACK -> send cycle when bif transiently hits 0.
        let mut sender = test_sender();
        let size = sender.max_datagram_size;
        let rtt = Duration::from_millis(100);

        // Fill the pipe.
        for _ in 0..sender.initial_congestion_window_packets {
            sender.send_packet(size);
        }

        sender.update_rtt(rtt);
        sender.advance_time(rtt);

        // Trigger a loss to enter recovery and reduce cwnd.
        let initial_cwnd = sender.congestion_window;
        sender.lose_n_packets(1, size, None);
        let post_loss_cwnd = sender.congestion_window;
        assert_eq!(post_loss_cwnd, (initial_cwnd as f64 * BETA_CUBIC) as usize);
        let initial_recovery_start_time =
            sender.congestion_recovery_start_time.unwrap();
        assert_eq!(initial_recovery_start_time, sender.time);

        // ACK remaining in-flight packets to exit recovery.
        sender.ack_n_packets(sender.initial_congestion_window_packets - 1, size);
        assert_eq!(sender.bytes_in_flight, 0);

        // Now simulate the problematic pattern: send a small burst at
        // minimum cwnd, ACK it (bif drops to 0), advance one RTT, repeat.
        // With the bug, recovery_start_time would advance on every
        // cycle, trapping cwnd.  With the fix, cwnd must grow.
        let packets_per_burst = cmp::max(1, sender.congestion_window / size);

        for _ in 0..20 {
            for _ in 0..packets_per_burst {
                sender.send_packet(size);
            }

            sender.advance_time(rtt);
            sender.ack_n_packets(packets_per_burst, size);
            assert_eq!(sender.bytes_in_flight, 0);
        }

        // cwnd must have grown beyond the post-loss value.
        assert!(
            sender.congestion_window > post_loss_cwnd,
            "cwnd stuck at {} (post-loss {}): perpetual recovery trap",
            sender.congestion_window,
            post_loss_cwnd,
        );
        // Recovery start hasn't changed.
        assert_eq!(
            sender.congestion_recovery_start_time.unwrap() -
                initial_recovery_start_time,
            Duration::ZERO,
            "epoch should not have shifted without idle gap",
        );
    }

    #[test]
    fn cubic_genuine_idle_epoch_shift() {
        // After a loss + recovery, a long idle period (seconds) should
        // shift the epoch so that cwnd growth resumes from where it
        // left off rather than jumping.
        let mut sender = test_sender();
        let test_start = sender.time;
        let size = sender.max_datagram_size;
        let rtt = Duration::from_millis(100);

        // Fill the pipe and trigger loss.
        for _ in 0..sender.initial_congestion_window_packets {
            sender.send_packet(size);
        }
        sender.update_rtt(rtt);
        sender.advance_time(rtt);
        sender.lose_n_packets(1, size, None);

        let initial_recovery_start =
            sender.congestion_recovery_start_time.unwrap();
        assert_eq!(
            initial_recovery_start,
            test_start + rtt,
            "Recovery start is set",
        );

        let post_loss_cwnd = sender.congestion_window;

        // ACK remaining to exit recovery.
        sender.ack_n_packets(sender.initial_congestion_window_packets - 1, size);

        // App-limited like behavior
        // Long idle: 5 seconds of silence.
        let idle_duration = Duration::from_secs(5);
        sender.advance_time(idle_duration);

        // Resume sending and ACKing.
        let packets_per_burst = cmp::max(1, sender.congestion_window / size);

        for _ in 0..packets_per_burst {
            sender.send_packet(size);
        }
        sender.advance_time(rtt);
        sender.ack_n_packets(packets_per_burst, size);

        // After one RTT of sending post-idle, cwnd should not have
        // shrunk.
        assert_eq!(sender.congestion_window, post_loss_cwnd);

        // Verify recovery_start_time was shifted forward (i.e., the
        // idle shift logic ran).
        let recovery_start = sender.congestion_recovery_start_time.unwrap();
        assert!(
            recovery_start >
                sender.cubic_state.last_sent_time.unwrap() - idle_duration,
            "epoch should have been shifted forward by idle period",
        );
        assert_eq!(
            recovery_start - sender.cubic_state.last_sent_time.unwrap(),
            Duration::ZERO,
            "epoch should have been shifted forward by idle period",
        );
        assert_eq!(
            recovery_start - initial_recovery_start,
            idle_duration,
            "Recovery start should have moved forward by the idle duration",
        );
    }

    #[test]
    fn cubic_zero_bytes_sent_no_epoch_shift() {
        // A zero-byte packet (e.g. PADDING-only) must NOT shift
        // congestion_recovery_start_time or update last_sent_time.
        let mut sender = test_sender();
        let size = sender.max_datagram_size;
        let rtt = Duration::from_millis(100);

        // Fill pipe, trigger loss to set congestion_recovery_start_time.
        for _ in 0..sender.initial_congestion_window_packets {
            sender.send_packet(size);
        }
        sender.update_rtt(rtt);
        sender.advance_time(rtt);
        sender.lose_n_packets(1, size, None);

        // ACK everything → bif = 0.
        sender.ack_n_packets(sender.initial_congestion_window_packets - 1, size);
        assert_eq!(sender.bytes_in_flight, 0);

        // Record state before zero-byte send.
        let recovery_start_before = sender.congestion_recovery_start_time;
        let last_sent_before = sender.cubic_state.last_sent_time;

        // Advance time so any shift would be visible.
        sender.advance_time(Duration::from_millis(500));

        // Send a zero-byte packet (simulates PADDING-only).
        sender.send_packet(0);

        // Neither recovery_start_time nor last_sent_time should change.
        assert_eq!(
            sender.congestion_recovery_start_time, recovery_start_before,
            "recovery_start_time must not shift on zero-byte send",
        );
        assert_eq!(
            sender.cubic_state.last_sent_time, last_sent_before,
            "last_sent_time must not update on zero-byte send",
        );
    }
}
