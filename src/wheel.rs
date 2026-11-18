//! The hierarchical timing wheel (Varghese and Lauck, 1987): one per reactor
//! worker. Six levels of 64 slots cover 64^6 ticks (about 2.2 years at 1 ms);
//! later deadlines wait on an overflow list.
//!
//! - Insert and cancel are O(1) and allocate nothing once the arena reached
//!   its working size: entries live in one `Vec`, linked by index.
//! - Lazy extension: moving a deadline later only stores it. The entry stays
//!   where it is and is placed again when its old slot comes up, so a read
//!   that pushes the idle deadline costs one store.
//! - A timer never fires before its deadline.
//! - Tickless: [`Wheel::next_expiry`] finds the next occupied slot with a
//!   64-bit occupancy map per level, so a quiet worker sleeps in the kernel.
//! - Expired timers come out one at a time and in deadline order, so a caller
//!   can bound its work per loop iteration; after a clock jump every expired
//!   timer fires once.

use std::time::{Duration, Instant};

const LEVELS: usize = 6;
const SLOT_BITS: u32 = 6;
const SLOTS: usize = 1 << SLOT_BITS;
const SLOT_MASK: u64 = (SLOTS as u64) - 1;
/// Ticks one wheel rotation of the top level covers: 64^6.
const SPAN: u64 = 1 << (SLOT_BITS * LEVELS as u32);
const NONE: u32 = u32::MAX;

/// Where an entry is linked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Place {
    Free,
    Slot(u8, u8),
    Overflow,
    Due,
}

#[derive(Clone, Copy, Debug)]
struct Entry {
    deadline: u64,
    payload: u64,
    next: u32,
    prev: u32,
    generation: u32,
    place: Place,
}

/// A timer in a [`Wheel`]. The generation makes a stale id harmless: after the
/// timer fired or was cancelled, every call with this id does nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct TimerId {
    index: u32,
    generation: u32,
}

/// Converts between `Instant` and ticks: deadlines round up, the current time
/// rounds down, so a timer can never fire early.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Ticks {
    start: Instant,
    tick_nanos: u64,
}

impl Ticks {
    pub(crate) fn new(start: Instant, tick: Duration) -> Ticks {
        let nanos = u64::try_from(tick.as_nanos()).unwrap_or(u64::MAX);
        Ticks {
            start,
            tick_nanos: nanos.max(1),
        }
    }

    fn nanos(&self, at: Instant) -> u64 {
        let d = at.saturating_duration_since(self.start);
        u64::try_from(d.as_nanos()).unwrap_or(u64::MAX)
    }

    /// The tick `at` falls in (rounded down).
    pub(crate) fn now(&self, at: Instant) -> u64 {
        self.nanos(at) / self.tick_nanos
    }

    /// The first tick not before `at` (rounded up).
    pub(crate) fn deadline(&self, at: Instant) -> u64 {
        self.nanos(at).div_ceil(self.tick_nanos)
    }

    /// How long from `now` until `tick` starts.
    pub(crate) fn until(&self, tick: u64, now: Instant) -> Duration {
        let at = u128::from(tick) * u128::from(self.tick_nanos);
        let at = u64::try_from(at).unwrap_or(u64::MAX);
        Duration::from_nanos(at.saturating_sub(self.nanos(now)))
    }
}

/// The wheel.
#[derive(Debug)]
pub(crate) struct Wheel {
    entries: Vec<Entry>,
    free: u32,
    heads: [[u32; SLOTS]; LEVELS],
    occupied: [u64; LEVELS],
    overflow: u32,
    due_head: u32,
    due_tail: u32,
    /// Every slot before this tick has been processed.
    elapsed: u64,
    live: usize,
}

/// A fired timer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Fired {
    pub(crate) id: TimerId,
    pub(crate) payload: u64,
}

impl Wheel {
    /// An empty wheel with room for `capacity` timers before it grows.
    pub(crate) fn with_capacity(capacity: usize) -> Wheel {
        Wheel {
            entries: Vec::with_capacity(capacity),
            free: NONE,
            heads: [[NONE; SLOTS]; LEVELS],
            occupied: [0; LEVELS],
            overflow: NONE,
            due_head: NONE,
            due_tail: NONE,
            elapsed: 0,
            live: 0,
        }
    }

    /// Timers waiting to fire.
    pub(crate) fn len(&self) -> usize {
        self.live
    }

    /// Starts a timer. A deadline at or before the current tick fires at the
    /// next [`Wheel::pop_expired`].
    pub(crate) fn insert(&mut self, deadline: u64, payload: u64) -> TimerId {
        let index = self.alloc();
        let e = &mut self.entries[index as usize];
        e.deadline = deadline;
        e.payload = payload;
        let generation = e.generation;
        self.live += 1;
        self.place(index);
        TimerId { index, generation }
    }

    /// Stops a timer; `false` when it already fired or was cancelled.
    pub(crate) fn cancel(&mut self, id: TimerId) -> bool {
        if !self.is_live(id) {
            return false;
        }
        self.unlink(id.index);
        self.release(id.index);
        true
    }

    /// Moves a timer's deadline; `false` when it already fired or was
    /// cancelled. Later is one store (lazy extension); earlier moves the entry.
    pub(crate) fn reschedule(&mut self, id: TimerId, deadline: u64) -> bool {
        if !self.is_live(id) {
            return false;
        }
        let current = self.entries[id.index as usize].deadline;
        self.entries[id.index as usize].deadline = deadline;
        if deadline < current {
            self.unlink(id.index);
            self.place(id.index);
        }
        true
    }

    /// Whether the timer is still waiting.
    pub(crate) fn is_live(&self, id: TimerId) -> bool {
        self.entries
            .get(id.index as usize)
            .is_some_and(|e| e.generation == id.generation && e.place != Place::Free)
    }

    /// The next expired timer at time `now`, in deadline order, or `None` when
    /// nothing has expired. Call it in a loop with a bound per iteration.
    pub(crate) fn pop_expired(&mut self, now: u64) -> Option<Fired> {
        // A clock that went back (a user `Clock` that broke its contract) is held at
        // the wheel's own time: placing an entry due between the two would otherwise
        // put it straight back on the due list, for ever.
        let now = now.max(self.elapsed);
        loop {
            if self.due_head != NONE {
                let index = self.due_head;
                let e = self.entries[index as usize];
                self.unlink(index);
                if e.deadline > now {
                    // Extended while it waited: not due yet.
                    self.place_after(index, now);
                    continue;
                }
                let id = TimerId {
                    index,
                    generation: e.generation,
                };
                self.release(index);
                return Some(Fired {
                    id,
                    payload: e.payload,
                });
            }
            if !self.advance(now) {
                return None;
            }
        }
    }

    /// The tick the next occupied slot starts (at or before the first real
    /// deadline: an extended entry or an entry in a high level may wake the
    /// caller early, to be placed again, but never fire early).
    pub(crate) fn next_expiry(&self) -> Option<u64> {
        if self.due_head != NONE {
            return Some(self.elapsed);
        }
        let in_wheel = (0..LEVELS)
            .find_map(|l| self.next_in_level(l))
            .map(|(_, _, t)| t);
        if self.overflow == NONE {
            return in_wheel;
        }
        let boundary = self.top_boundary();
        Some(in_wheel.map_or(boundary, |t| t.min(boundary)))
    }

    fn top_boundary(&self) -> u64 {
        (self.elapsed / SPAN).saturating_add(1).saturating_mul(SPAN)
    }

    /// Moves time forward to the next occupied slot at or before `now`, or to
    /// `now`. `true` when entries may have become due.
    fn advance(&mut self, now: u64) -> bool {
        // The lowest level with a slot gives the nearest tick: a higher level's
        // slot starts after every slot of the levels below it.
        let next = (0..LEVELS).find_map(|l| self.next_in_level(l));
        if let Some((level, slot, tick)) = next {
            if tick <= now {
                self.elapsed = tick;
                self.open_slot(level, slot);
                return true;
            }
        }
        if self.overflow != NONE {
            let boundary = self.top_boundary();
            if boundary <= now {
                self.elapsed = boundary;
                self.reopen_overflow();
                return true;
            }
        }
        if now > self.elapsed {
            self.elapsed = now;
        }
        false
    }

    /// The first occupied slot of `level` from the current position.
    fn next_in_level(&self, level: usize) -> Option<(usize, usize, u64)> {
        let map = self.occupied[level];
        if map == 0 {
            return None;
        }
        let shift = SLOT_BITS * level as u32;
        let position = (self.elapsed >> shift) & SLOT_MASK;
        // Slots behind the position belong to the next rotation; `place` never
        // puts an entry there, so the map from the position upwards holds them all.
        let ahead = map >> position;
        let slot = if ahead != 0 {
            position + u64::from(ahead.trailing_zeros())
        } else {
            u64::from(map.trailing_zeros())
        };
        let range = 1u64 << (shift + SLOT_BITS);
        let base = self.elapsed & !(range - 1);
        let tick = base + (slot << shift);
        Some((level, slot as usize, tick.max(self.elapsed)))
    }

    /// Moves every entry of a slot to where it belongs now that `elapsed` reached it.
    fn open_slot(&mut self, level: usize, slot: usize) {
        let mut index = self.heads[level][slot];
        self.heads[level][slot] = NONE;
        self.occupied[level] &= !(1u64 << slot);
        while index != NONE {
            let next = self.entries[index as usize].next;
            self.place(index);
            index = next;
        }
    }

    fn reopen_overflow(&mut self) {
        let mut index = self.overflow;
        self.overflow = NONE;
        while index != NONE {
            let next = self.entries[index as usize].next;
            self.place(index);
            index = next;
        }
    }

    /// Links an unlinked entry by its deadline.
    fn place(&mut self, index: u32) {
        let deadline = self.entries[index as usize].deadline;
        if deadline <= self.elapsed {
            self.push_due(index);
            return;
        }
        // The highest bit in which the deadline differs from `elapsed` picks the
        // level: everything above it is shared, so the slot lies ahead in this rotation.
        let differ = deadline ^ self.elapsed;
        let level = ((63 - differ.leading_zeros()) / SLOT_BITS) as usize;
        if level >= LEVELS {
            let head = self.overflow;
            self.link(index, head, Place::Overflow);
            if head != NONE {
                self.entries[head as usize].prev = index;
            }
            self.overflow = index;
            return;
        }
        let slot = ((deadline >> (SLOT_BITS * level as u32)) & SLOT_MASK) as usize;
        let head = self.heads[level][slot];
        self.link(index, head, Place::Slot(level as u8, slot as u8));
        if head != NONE {
            self.entries[head as usize].prev = index;
        }
        self.heads[level][slot] = index;
        self.occupied[level] |= 1u64 << slot;
    }

    /// Places an entry popped from the due list whose deadline moved past `now`.
    fn place_after(&mut self, index: u32, now: u64) {
        if now > self.elapsed {
            // Everything before `now` is handled: the due list is drained first,
            // and `advance` only moves past slots it opened.
            let _ = self.advance_to_entry(now);
        }
        self.place(index);
    }

    fn advance_to_entry(&mut self, now: u64) -> bool {
        // `elapsed` may move only up to the next occupied slot.
        match (0..LEVELS).find_map(|l| self.next_in_level(l)) {
            Some((_, _, tick)) if tick <= now => false,
            _ if self.overflow != NONE && self.top_boundary() <= now => false,
            _ => {
                self.elapsed = now;
                true
            }
        }
    }

    fn link(&mut self, index: u32, next: u32, place: Place) {
        let e = &mut self.entries[index as usize];
        e.next = next;
        e.prev = NONE;
        e.place = place;
    }

    fn push_due(&mut self, index: u32) {
        let tail = self.due_tail;
        let e = &mut self.entries[index as usize];
        e.next = NONE;
        e.prev = tail;
        e.place = Place::Due;
        if tail == NONE {
            self.due_head = index;
        } else {
            self.entries[tail as usize].next = index;
        }
        self.due_tail = index;
    }

    fn unlink(&mut self, index: u32) {
        let e = self.entries[index as usize];
        if e.prev != NONE {
            self.entries[e.prev as usize].next = e.next;
        }
        if e.next != NONE {
            self.entries[e.next as usize].prev = e.prev;
        }
        match e.place {
            Place::Slot(level, slot) => {
                let (level, slot) = (usize::from(level), usize::from(slot));
                if self.heads[level][slot] == index {
                    self.heads[level][slot] = e.next;
                    if e.next == NONE {
                        self.occupied[level] &= !(1u64 << slot);
                    }
                }
            }
            Place::Overflow => {
                if self.overflow == index {
                    self.overflow = e.next;
                }
            }
            Place::Due => {
                if self.due_head == index {
                    self.due_head = e.next;
                }
                if self.due_tail == index {
                    self.due_tail = e.prev;
                }
            }
            Place::Free => {}
        }
    }

    fn alloc(&mut self) -> u32 {
        if self.free != NONE {
            let index = self.free;
            self.free = self.entries[index as usize].next;
            return index;
        }
        self.entries.push(Entry {
            deadline: 0,
            payload: 0,
            next: NONE,
            prev: NONE,
            generation: 0,
            place: Place::Free,
        });
        (self.entries.len() - 1) as u32
    }

    fn release(&mut self, index: u32) {
        let free = self.free;
        let e = &mut self.entries[index as usize];
        e.generation = e.generation.wrapping_add(1);
        e.place = Place::Free;
        e.next = free;
        e.prev = NONE;
        self.free = index;
        self.live -= 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn drain(w: &mut Wheel, now: u64) -> Vec<u64> {
        let mut out = Vec::new();
        while let Some(f) = w.pop_expired(now) {
            out.push(f.payload);
        }
        out
    }

    #[test]
    fn test_fires_at_its_tick_and_never_before() {
        let mut w = Wheel::with_capacity(8);
        w.insert(100, 1);
        assert!(drain(&mut w, 99).is_empty());
        assert_eq!(drain(&mut w, 100), vec![1]);
        assert!(drain(&mut w, 100).is_empty());
        assert_eq!(w.len(), 0);
    }

    /// Edge case 53: a deadline exactly at the current tick fires this tick.
    #[test]
    fn test_deadline_at_the_current_tick() {
        let mut w = Wheel::with_capacity(8);
        assert!(drain(&mut w, 50).is_empty());
        w.insert(50, 7);
        assert_eq!(drain(&mut w, 50), vec![7]);
    }

    /// A clock that goes back cannot hang the wheel: an entry due between the two
    /// times fires instead of circling the due list.
    #[test]
    fn test_clock_going_back_does_not_spin() {
        let mut w = Wheel::with_capacity(8);
        assert!(drain(&mut w, 1_000).is_empty());
        w.insert(990, 7);
        assert_eq!(drain(&mut w, 980), vec![7]);
        w.insert(1_500, 8);
        assert!(drain(&mut w, 900).is_empty());
        assert_eq!(drain(&mut w, 1_500), vec![8]);
    }

    /// Edge case 54: a deadline in the past fires at the next look.
    #[test]
    fn test_deadline_in_the_past() {
        let mut w = Wheel::with_capacity(8);
        assert!(drain(&mut w, 1_000).is_empty());
        w.insert(10, 7);
        assert_eq!(w.next_expiry(), Some(1_000));
        assert_eq!(drain(&mut w, 1_001), vec![7]);
    }

    /// Edge case 55: beyond 64^6 ticks: the overflow list, across the wrap.
    #[test]
    fn test_overflow_fires_across_the_wrap() {
        let mut w = Wheel::with_capacity(8);
        let far = SPAN * 3 + 12_345;
        w.insert(far, 1);
        w.insert(SPAN + 7, 2);
        w.insert(5, 3);
        assert_eq!(drain(&mut w, 5), vec![3]);
        assert_eq!(w.next_expiry(), Some(SPAN));
        assert!(drain(&mut w, SPAN).is_empty());
        assert_eq!(drain(&mut w, SPAN + 7), vec![2]);
        assert!(drain(&mut w, far - 1).is_empty());
        assert_eq!(drain(&mut w, far), vec![1]);
        assert_eq!(w.len(), 0);
    }

    /// Edge case 56: 100,000 timers in one slot come out one at a time.
    #[test]
    fn test_many_timers_in_one_slot_are_bounded_by_the_caller() {
        let mut w = Wheel::with_capacity(100_000);
        for i in 0..100_000 {
            w.insert(10, i);
        }
        let mut seen = 0;
        while w.len() > 0 {
            let mut this_round = 0;
            while this_round < 1_024 {
                if w.pop_expired(10).is_none() {
                    break;
                }
                this_round += 1;
            }
            assert!(this_round <= 1_024);
            seen += this_round;
        }
        assert_eq!(seen, 100_000);
    }

    /// Edge case 57: extended a million times: one entry, fires once.
    #[test]
    fn test_extended_a_million_times_fires_once() {
        let mut w = Wheel::with_capacity(1);
        let id = w.insert(10, 1);
        let mut deadline = 10;
        let mut now = 0;
        for _ in 0..1_000_000 {
            deadline += 2;
            now += 2;
            assert!(w.reschedule(id, deadline));
            assert!(w.pop_expired(now).is_none());
        }
        assert_eq!(w.entries.len(), 1);
        assert_eq!(drain(&mut w, deadline), vec![1]);
        assert!(!w.is_live(id));
    }

    /// An entry extended while it sits in a slot moves on when that slot opens.
    #[test]
    fn test_extension_places_the_entry_again() {
        let mut w = Wheel::with_capacity(4);
        let id = w.insert(10, 1);
        assert!(w.reschedule(id, 500));
        assert!(drain(&mut w, 10).is_empty());
        assert!(w.is_live(id));
        assert!(drain(&mut w, 499).is_empty());
        assert_eq!(drain(&mut w, 500), vec![1]);
    }

    #[test]
    fn test_moving_a_deadline_earlier() {
        let mut w = Wheel::with_capacity(4);
        let id = w.insert(10_000, 1);
        assert!(w.reschedule(id, 20));
        assert_eq!(drain(&mut w, 20), vec![1]);
    }

    /// Edge case 58: an id from before the timer fired does nothing.
    #[test]
    fn test_cancel_after_firing_is_ignored() {
        let mut w = Wheel::with_capacity(4);
        let a = w.insert(10, 1);
        assert_eq!(w.pop_expired(10).map(|f| f.payload), Some(1));
        assert!(!w.cancel(a));
        // The slot is reused; the old id must not touch the new timer.
        let b = w.insert(20, 2);
        assert_eq!(a.index, b.index);
        assert!(!w.cancel(a));
        assert!(!w.reschedule(a, 30));
        assert!(w.is_live(b));
        assert!(w.cancel(b));
        assert!(!w.cancel(b));
    }

    /// Edge case 59: a jump of an hour: every expired timer once, in order.
    #[test]
    fn test_clock_jump_fires_everything_in_order() {
        let mut w = Wheel::with_capacity(5_000);
        let hour = 3_600_000u64;
        // Inserted out of order, across levels.
        for i in (0..5_000u64).rev() {
            w.insert(1 + i * 700, i);
        }
        let got = drain(&mut w, hour);
        let expired = (0..5_000u64).filter(|i| i * 700 < hour).count();
        assert_eq!(got.len(), expired);
        assert!(got.windows(2).all(|p| p[0] < p[1]), "in deadline order");
        assert_eq!(w.len(), 5_000 - expired);
    }

    /// Edge case 60: a frozen clock: nothing fires, nothing spins.
    #[test]
    fn test_frozen_clock_fires_nothing() {
        let mut w = Wheel::with_capacity(4);
        w.insert(1_000, 1);
        for _ in 0..1_000 {
            assert!(w.pop_expired(5).is_none());
        }
        assert_eq!(w.len(), 1);
    }

    #[test]
    fn test_next_expiry_is_never_after_the_first_deadline() {
        let mut w = Wheel::with_capacity(8);
        assert_eq!(w.next_expiry(), None);
        w.insert(70_000, 1);
        let first = w.next_expiry().unwrap();
        assert!(first <= 70_000);
        w.insert(3, 2);
        assert_eq!(w.next_expiry(), Some(3));
        assert_eq!(drain(&mut w, 3), vec![2]);
        assert!(w.next_expiry().unwrap() <= 70_000);
    }

    #[test]
    fn test_cancel_clears_the_occupancy_map() {
        let mut w = Wheel::with_capacity(4);
        let a = w.insert(9, 1);
        let b = w.insert(9, 2);
        assert!(w.cancel(a));
        assert_eq!(w.next_expiry(), Some(9));
        assert!(w.cancel(b));
        assert_eq!(w.next_expiry(), None);
    }

    #[test]
    fn test_no_allocation_after_warm_up() {
        let mut w = Wheel::with_capacity(16);
        let ids: Vec<_> = (0..16).map(|i| w.insert(100 + i, i)).collect();
        for id in ids {
            w.cancel(id);
        }
        let cap = w.entries.capacity();
        for round in 0..10_000u64 {
            let id = w.insert(200 + round, round);
            w.cancel(id);
        }
        assert_eq!(w.entries.capacity(), cap);
        assert_eq!(w.entries.len(), 16);
    }

    #[test]
    fn test_ticks_round_deadlines_up_and_now_down() {
        let start = Instant::now();
        let t = Ticks::new(start, Duration::from_millis(10));
        let at = start + Duration::from_millis(15);
        assert_eq!(t.now(at), 1);
        assert_eq!(t.deadline(at), 2);
        assert_eq!(t.deadline(start + Duration::from_millis(20)), 2);
        assert_eq!(t.until(2, at), Duration::from_millis(5));
        assert_eq!(t.until(1, at), Duration::ZERO);
    }

    /// Against a sorted-list model: random inserts, cancels, extensions, jumps.
    #[test]
    fn prop_matches_a_sorted_model() {
        let mut seed = 0x9E37_79B9_7F4A_7C15u64;
        let mut rand = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..50 {
            let mut w = Wheel::with_capacity(64);
            let mut model: Vec<(u64, u64, TimerId)> = Vec::new();
            let mut now = 0u64;
            let mut next_payload = 0u64;
            for _ in 0..3_000 {
                match rand() % 10 {
                    0..=4 => {
                        let spread = 1u64 << (rand() % 40);
                        let deadline = now + rand() % spread;
                        let id = w.insert(deadline, next_payload);
                        model.push((deadline, next_payload, id));
                        next_payload += 1;
                    }
                    5 if !model.is_empty() => {
                        let i = (rand() as usize) % model.len();
                        let (_, _, id) = model.swap_remove(i);
                        assert!(w.cancel(id));
                    }
                    6 if !model.is_empty() => {
                        let i = (rand() as usize) % model.len();
                        let deadline = now + rand() % (1 << 20);
                        model[i].0 = deadline;
                        assert!(w.reschedule(model[i].2, deadline));
                    }
                    _ => {
                        now += rand() % (1u64 << (rand() % 24));
                        let mut fired = drain(&mut w, now);
                        fired.sort_unstable();
                        let mut due: Vec<u64> =
                            model.iter().filter(|m| m.0 <= now).map(|m| m.1).collect();
                        due.sort_unstable();
                        assert_eq!(fired, due, "at {now}");
                        model.retain(|m| m.0 > now);
                    }
                }
                assert_eq!(w.len(), model.len());
            }
        }
    }

    /// B-8: `cargo test --release --lib bench_wheel -- --ignored --nocapture`.
    #[test]
    #[ignore = "a benchmark"]
    fn bench_wheel() {
        const N: u64 = 1_000_000;
        let mut w = Wheel::with_capacity(N as usize);
        let t = std::time::Instant::now();
        let ids: Vec<_> = (0..N).map(|i| w.insert(1_000 + i % 100_000, i)).collect();
        let insert = t.elapsed();
        let t = std::time::Instant::now();
        for (i, id) in ids.iter().enumerate() {
            std::hint::black_box(w.reschedule(*id, 200_000 + i as u64 % 100_000));
        }
        let extend = t.elapsed();
        let t = std::time::Instant::now();
        for id in &ids {
            std::hint::black_box(w.cancel(*id));
        }
        let cancel = t.elapsed();
        let per = |d: std::time::Duration| d.as_nanos() as f64 / N as f64;
        println!(
            "B-8 ns per operation: insert {:.1}, lazy extend {:.1}, cancel {:.1}",
            per(insert),
            per(extend),
            per(cancel)
        );
    }
}

/// The fuzz target `wheel`: operations decoded from `data` run against a plain
/// map of deadlines; every entry fires exactly once, never before its tick, and
/// cancelled or rescheduled ones follow the model.
#[cfg(fuzzing)]
pub(crate) fn fuzz_wheel(data: &[u8]) {
    use std::collections::BTreeMap;
    let mut w = Wheel::with_capacity(16);
    let mut model: BTreeMap<u64, u64> = BTreeMap::new();
    let mut ids: Vec<(TimerId, u64)> = Vec::new();
    let mut now = 0u64;
    let mut next = 0u64;
    for op in data.chunks(4) {
        let arg = op.get(1..).map_or(0u64, |b| {
            b.iter().fold(0u64, |a, &x| (a << 8) | u64::from(x))
        });
        match op[0] % 4 {
            0 => {
                // Deadlines up to past the wheel's top level, some already due.
                let deadline = now.saturating_sub(4).saturating_add(arg << (op[0] >> 5));
                let id = w.insert(deadline, next);
                model.insert(next, deadline);
                ids.push((id, next));
                next += 1;
            }
            1 if !ids.is_empty() => {
                let (id, p) = ids.swap_remove(arg as usize % ids.len());
                assert_eq!(w.cancel(id), model.remove(&p).is_some());
            }
            2 if !ids.is_empty() => {
                let (id, p) = ids[arg as usize % ids.len()];
                let deadline = now.saturating_add(arg & 0xffff);
                let live = model.contains_key(&p);
                assert_eq!(w.reschedule(id, deadline), live);
                if live {
                    model.insert(p, deadline);
                }
            }
            _ => {
                now = now.saturating_add(arg & 0x3ffff);
                while let Some(f) = w.pop_expired(now) {
                    let deadline = model.remove(&f.payload).expect("fired once");
                    assert!(deadline <= now, "fired early: {deadline} > {now}");
                }
                assert!(model.values().all(|&d| d > now), "missed a deadline");
            }
        }
        assert_eq!(w.len(), model.len());
    }
}
