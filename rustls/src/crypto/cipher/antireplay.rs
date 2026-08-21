//! Replay protection for Datagram TLS.
//!
//! Datagram TLS records include an epoch number (used to select key material) and a record sequence
//! number, used for replay protection within an epoch. This module implements the sliding window
//! replay protection procedure described in [draft-ietf-tls-rfc9147bis][1] and [RFC 6347][2].
//!
//! [1]: https://datatracker.ietf.org/doc/html/draft-ietf-tls-rfc9147bis-02#section-4.5.1
//! [2]: https://www.rfc-editor.org/info/rfc6347/#section-4.1.2.6

/// Sliding window of observed sequence numbers.
///
/// Implements the sliding window procedure described in [draft-ietf-tls-rfc9147bis][1] and [
/// RFC 6347][2].
///
/// [1]: https://datatracker.ietf.org/doc/html/draft-ietf-tls-rfc9147bis-02#section-4.5.1
/// [2]: https://www.rfc-editor.org/info/rfc6347/#section-4.1.2.6
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ReplayWindow {
    /// The next expected sequence number in this epoch.
    ///
    /// That is, one more than the highest sequence number ever observed. If the value is 0, then no
    /// sequence numbers have ever been observed. This is the right hand side of the sliding window.
    next_expected_seq: u64,
    /// Observed sequence numbers in the window.
    ///
    /// Each bit represents a sequence number relative to `Self::next_expected_seq`, but not
    /// including it, since that sequence number has implicitly never been observed.
    ///
    /// Bit `n` being set indicates that sequence number `Self::next_expected_seq - (n + 1)` has
    /// been observed.
    observed_seq: u128,
}

impl ReplayWindow {
    /// Observe a sequence number, rejecting it if it is a replay.
    ///
    /// Sequence numbers that are too old (past the left end of the window) are rejected. Sequence
    /// numbers that are within the window but have previously been observed are rejected. Sequence
    /// numbers newer than anything previously observed are accepted, and move the window forward.
    pub(crate) fn observe(&mut self, seq: u64) -> Result<(), AntiReplay> {
        // Reject sequence numbers past left end of window: seq < self.next_expected_seq - 128
        // Re-arrange terms to avoid underflow.
        if seq + (u128::BITS as u64) < self.next_expected_seq {
            return Err(AntiReplay::TooOld);
        }

        if seq >= self.next_expected_seq {
            let shift = u32::try_from(seq - self.next_expected_seq)
                .map_err(|_| AntiReplay::TooFarInTheFuture)?
                + 1;

            // If shift is bigger than 128, then all the bits of self.observed_seq get shifted off
            // the end and the value is reset to 0.
            self.observed_seq = self.observed_seq.unbounded_shr(shift);
            self.next_expected_seq = seq + 1;
            self.observed_seq |= 1 << u128::BITS - 1;

            return Ok(());
        }

        let diff = self.next_expected_seq - seq;
        assert!(diff <= 128);

        let mask = 1 << 128 - diff;
        if self.observed_seq & mask == mask {
            return Err(AntiReplay::Replay);
        }

        self.observed_seq |= mask;

        Ok(())
    }
}

/// Reasons that a record might be rejected as replayed.
#[derive(Debug, Copy, Clone, PartialEq)]
#[non_exhaustive]
pub enum AntiReplay {
    /// The endpoint received a replayed DTLS record ([1], [2]).
    ///
    /// [1]: https://datatracker.ietf.org/doc/html/rfc6347#section-4.1.2.6
    /// [2]: https://datatracker.ietf.org/doc/html/rfc9147#section-4.5.1
    Replay,

    /// The endpoint received a DTLS record that is too old ([1], [2]).
    ///
    /// [1]: https://datatracker.ietf.org/doc/html/rfc6347#section-4.1.2.6
    /// [2]: https://datatracker.ietf.org/doc/html/rfc9147#section-4.5.1
    TooOld,

    /// The endpoint received a DTLS record that is from too far in the future.
    TooFarInTheFuture,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reject_too_old() {
        let mut window = ReplayWindow::default();
        // Set right end of window to 200
        window.observe(200).unwrap();
        assert_eq!(window.next_expected_seq, 201);

        assert_eq!(window.observe(1).unwrap_err(), AntiReplay::TooOld);
        // Boundary condition: the first sequence number that's outside the window
        assert_eq!(
            window
                .observe(200 - (128 + 1))
                .unwrap_err(),
            AntiReplay::TooOld
        );
    }

    #[test]
    fn accept_newer() {
        let mut window = ReplayWindow::default();
        window.observe(1).unwrap();
        assert_eq!(window.next_expected_seq, 2);
        window.observe(2).unwrap();
        assert_eq!(window.next_expected_seq, 3);
        window.observe(400).unwrap();
        assert_eq!(window.next_expected_seq, 401);
    }

    #[test]
    fn accept_within_window() {
        let mut window = ReplayWindow::default();
        window.observe(200).unwrap();
        assert_eq!(window.next_expected_seq, 201);
        window.observe(150).unwrap();
        assert_eq!(window.next_expected_seq, 201);
    }

    #[test]
    fn reject_within_window() {
        let mut window = ReplayWindow::default();
        window.observe(200).unwrap();
        assert_eq!(window.next_expected_seq, 201);

        // Observe sequence numbers at left edge of window and somewhere in the middle.
        let left_edge = window.next_expected_seq - 128;
        let middle = window.next_expected_seq - 50;
        let right_edge = window.next_expected_seq - 1;
        window.observe(left_edge).unwrap();
        window.observe(middle).unwrap();
        assert_eq!(window.observe(right_edge).unwrap_err(), AntiReplay::Replay);
        // re-observing left edge and middle is now a replay.
        assert_eq!(window.observe(left_edge).unwrap_err(), AntiReplay::Replay);
        assert_eq!(window.observe(middle).unwrap_err(), AntiReplay::Replay);
    }

    #[test]
    fn slide_window() {
        let mut window = ReplayWindow::default();

        // Set right edge of window to 201 and observe sequence number at the left edge
        window.observe(200).unwrap();
        let left_edge = window.next_expected_seq - 128;
        window.observe(left_edge).unwrap();
        assert_eq!(window.next_expected_seq, 201);

        // Observe a higher sequence number. left_edge should slide out of the window, now being
        // rejected for being too old. right_edge is still in the window and should be rejected as a
        // replay.
        window.observe(201).unwrap();
        assert_eq!(window.next_expected_seq, 202);
        assert_eq!(window.observe(left_edge).unwrap_err(), AntiReplay::TooOld);
        assert_eq!(window.observe(200).unwrap_err(), AntiReplay::Replay);
    }
}
