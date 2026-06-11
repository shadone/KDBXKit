//
// Copyright (c) 2026, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#endif
import Foundation
import Synchronization

/// Zero a region with a function the compiler is forbidden from optimizing
/// away: `memset_s` (C11 Annex K) on Apple/BSD, `explicit_bzero` on Linux.
@inline(never)
func secureZero(_ ptr: UnsafeMutableRawPointer, _ len: Int) {
    guard len > 0 else { return }
    #if canImport(Darwin)
    memset_s(ptr, len, 0, len)
    #else
    explicit_bzero(ptr, len)
    #endif
}

/// A single page-aligned, `mlock`'d heap region that many ``SecureBytes``
/// secrets sub-allocate from.
///
/// ## Why arenas
///
/// `mlock` operates at page granularity, and a wired page counts in full
/// against the process footprint. A naive "one `mlock`'d allocation per
/// secret" design therefore wires a whole page (16 KiB on iOS) for a
/// 12-byte password — an ~800x amplification. A vault with thousands of
/// protected strings (entries x fields x history snapshots) wires enough
/// pages to blow past a memory-capped host like the iOS AutoFill
/// credential-provider extension (~220 MB), which jetsam then kills
/// mid-parse.
///
/// Packing many secrets into a shared `mlock`'d arena collapses the
/// wired-memory cost back down to roughly the sum of the secret bytes,
/// while keeping every secret pinned against swap exactly as before.
///
/// ## Lifetime
///
/// Each ``SecureBytes`` holds a strong reference to the arena its bytes
/// live in, so the arena is `munlock`'d and freed by ARC precisely when
/// its last secret is released — no global registry, no manual
/// live-count, no removal races. Per-secret zeroing still happens
/// promptly in `SecureBytes.deinit`; the arena's own `deinit` zeroes the
/// whole region again (defense in depth, covers alignment padding) before
/// unlocking and freeing.
final class SecureArena: @unchecked Sendable {
    /// Page-aligned, `mlock`'d region we own.
    let base: UnsafeMutableRawPointer
    /// Total bytes in the region (a multiple of the page size).
    let size: Int
    /// Bump cursor: next free offset. Mutated only under the allocator's
    /// lock (and only while this arena is the allocator's `current`).
    var used: Int = 0

    init(size: Int) {
        self.size = size
        let pageSize = Int(getpagesize())

        var ptr: UnsafeMutableRawPointer?
        let rc = posix_memalign(&ptr, pageSize, size)
        guard rc == 0, let buffer = ptr else {
            // System-level OOM on a page-aligned allocation the kernel
            // should always be able to satisfy — unrecoverable, same as
            // the old per-secret path. Crashing here is the honest answer.
            fatalError("SecureArena: posix_memalign failed (\(rc), requested \(size) bytes)")
        }
        base = buffer

        // Best-effort `mlock` — `RLIMIT_MEMLOCK` can refuse, in which case
        // the bytes still live here, just not pinned against swap.
        _ = mlock(buffer, size)
    }

    deinit {
        // Every live secret zeroed its own slice on its `deinit` already;
        // re-zero the whole region (incl. alignment padding) before
        // returning it, then drop the wired pages.
        secureZero(base, size)
        _ = munlock(base, size)
        free(base)
    }
}

/// Process-global sub-allocator that hands out slices of `mlock`'d
/// `SecureArena`s. Thread-safe via a single `Mutex` taken only on the
/// allocation path; reads and per-secret zeroing are lock-free.
final class SecureBytesArenaAllocator: Sendable {
    /// Shared bump arena, replaced when it fills. Holding it strong keeps
    /// at most one partially-used arena pinned while otherwise idle.
    private struct State {
        var current: SecureArena?
    }

    private let state = Mutex(State())

    /// Arena size, rounded up to a whole number of pages. 64 KiB packs
    /// thousands of typical secrets while bounding the slack pinned by a
    /// single long-lived secret to one arena.
    let arenaSize: Int
    /// Secrets larger than this get their own dedicated arena rather than
    /// wasting shared-arena space (half an arena keeps packing efficient).
    let largeThreshold: Int

    /// 16-byte slot alignment — generous for any access pattern over the
    /// raw bytes, and keeps adjacent secrets from sharing a cache line's
    /// worth of sub-alignment surprises.
    private let slotAlignment = 16

    init() {
        let pageSize = Int(getpagesize())
        let target = 64 * 1024
        arenaSize = ((max(target, pageSize) + pageSize - 1) / pageSize) * pageSize
        largeThreshold = arenaSize / 2
    }

    /// Reserve `count` bytes. Returns the owning arena (the caller must
    /// retain it for the lifetime of the bytes) and a pointer to the
    /// reserved slice. `count` must be > 0.
    func allocate(_ count: Int) -> (arena: SecureArena, pointer: UnsafeMutableRawPointer) {
        let aligned = (count + slotAlignment - 1) & ~(slotAlignment - 1)

        // Large secrets bypass the shared arena: a dedicated, page-rounded
        // region sized to the secret (the pre-arena behavior, minus the
        // per-secret amplification for the common small case).
        if aligned > largeThreshold {
            let pageSize = Int(getpagesize())
            let regionSize = ((aligned + pageSize - 1) / pageSize) * pageSize
            let arena = SecureArena(size: regionSize)
            arena.used = aligned
            return (arena, arena.base)
        }

        return state.withLock { st in
            // A fresh arena always fits an aligned request <= largeThreshold
            // (== arenaSize / 2), so this never loops.
            if st.current == nil || st.current!.used + aligned > st.current!.size {
                st.current = SecureArena(size: arenaSize)
            }
            let arena = st.current!
            let pointer = arena.base + arena.used
            arena.used += aligned
            return (arena, pointer)
        }
    }
}

/// The one process-wide allocator instance.
let secureBytesArenaAllocator = SecureBytesArenaAllocator()
