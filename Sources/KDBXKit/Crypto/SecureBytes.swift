//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
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

/// A page-locked, zero-on-deinit byte buffer for sensitive material.
///
/// Use `SecureBytes` for any cleartext key material that crosses the
/// library boundary: derived keys, key-file bytes, decrypted entry
/// strings, the inner-stream key. It's the answer to "how do we hold
/// secret bytes in a way that doesn't bleed to swap, doesn't survive
/// allocator reuse, and never gets handed to `Swift.String`?"
///
/// ## Mechanics
///
/// 1. Allocates a **page-aligned** heap region (`posix_memalign`) so
///    the entire region can be `mlock`'d.
/// 2. Asks the kernel to `mlock` the page so it can't be paged out to
///    disk (best-effort — `RLIMIT_MEMLOCK` can refuse and we proceed
///    anyway; a non-pinned page still holds the bytes, it just isn't
///    protected against swap).
/// 3. **Zeroes the bytes** when the last reference releases — via
///    `memset_s` on Apple/BSD or `explicit_bzero` on Linux. Both are
///    functions the compiler is forbidden from optimizing away. Then
///    `munlock`s and `free`s.
///
/// ## Access
///
/// Read access is via ``withUnsafeBytes(_:)`` — no subscript, no
/// `Data` getter, no `Array` accessor. The closure form bounds the
/// pointer's lifetime to a scope you control.
///
/// `SecureBytes` is a `final class` so copies share the underlying
/// buffer (cheap; single zeroing on last release), `deinit` is
/// reliable (structs can't have one), and `==` compares contents in
/// constant time rather than identity. The buffer is intentionally
/// **not** backed by a Swift `Array` or `Data` — those types may
/// reallocate or copy under the hood, defeating the zero-on-deinit
/// guarantee.
public final class SecureBytes: @unchecked Sendable, Equatable, CustomStringConvertible, Hashable {
    /// Page-aligned heap pointer we own.
    private let buffer: UnsafeMutableRawPointer
    /// Allocated size, rounded up to the page. Always ≥ count.
    private let allocated: Int
    /// Logical byte count exposed to callers.
    public let count: Int

    // MARK: - Initialisers

    /// Build a SecureBytes from any byte sequence. The source is copied into
    /// the page-locked buffer; the source's own backing memory is untouched
    /// (the caller is responsible for handling that source — if it was a
    /// `Data`/`[UInt8]`, the original bytes are still reachable through that
    /// reference until ARC collects them).
    public init(_ bytes: some Sequence<UInt8>) {
        let array = Array(bytes)
        let count = array.count
        self.count = count

        let pageSize = Int(getpagesize())
        // Always allocate at least one page so we have something to `mlock`.
        let logical = Swift.max(count, 1)
        let allocated = ((logical + pageSize - 1) / pageSize) * pageSize
        self.allocated = allocated

        var ptr: UnsafeMutableRawPointer?
        let rc = posix_memalign(&ptr, pageSize, allocated)
        guard rc == 0, let buffer = ptr else {
            // System-level OOM. Not reachable from adversarial input —
            // `posix_memalign` failure means the kernel refused a small
            // page-aligned allocation, which a host process can't recover
            // from in any useful way. Crashing here is the honest answer.
            fatalError("SecureBytes: posix_memalign failed (\(rc), requested \(allocated) bytes)")
        }
        self.buffer = buffer

        // Best-effort mlock — silently ignore failures (e.g. when the
        // RLIMIT_MEMLOCK rlimit prevents pinning; the page can still hold
        // the bytes, it just isn't pinned against swap).
        _ = mlock(buffer, allocated)

        if count > 0 {
            array.withUnsafeBufferPointer { source in
                buffer.copyMemory(from: source.baseAddress!, byteCount: count)
            }
        }
    }

    /// Convenience init from `Data`. Same caveat as the sequence init: the
    /// source `Data`'s backing bytes are not zeroed by us.
    public convenience init(_ data: Data) {
        self.init(Array(data))
    }

    /// Convenience init from a UTF-8 string. The source `String` is **still
    /// in the caller's memory** — Swift String can't be securely zeroed.
    /// Use this only at the boundary where plaintext arrives (typed
    /// passwords, JSON decoders, etc.); thereafter pass `SecureBytes` around.
    public convenience init(utf8 string: String) {
        self.init(Array(string.utf8))
    }

    /// Build an empty SecureBytes.
    public static var empty: SecureBytes { SecureBytes([] as [UInt8]) }

    /// Whether the buffer carries any bytes. Cheap convenience over
    /// `count == 0`; mirrors the standard-library shape of
    /// `Collection.isEmpty` so callers (and SwiftFormat's `isEmpty`
    /// rule) can reach for the natural form.
    public var isEmpty: Bool { count == 0 }

    deinit {
        // Zero the buffer with a function the compiler can't optimize
        // away. On Apple/BSD we use `memset_s` (C11 Annex K); on Linux
        // we use `explicit_bzero` (glibc ≥ 2.25, musl ≥ 1.1.20). Then
        // unlock the page and return it to the heap.
        #if canImport(Darwin)
        memset_s(buffer, allocated, 0, allocated)
        #else
        explicit_bzero(buffer, allocated)
        #endif
        _ = munlock(buffer, allocated)
        free(buffer)
    }

    // MARK: - Read access

    /// Lend the underlying bytes for the lifetime of `body`. The pointer is
    /// invalidated when `body` returns — do not let it escape.
    @discardableResult
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try body(UnsafeRawBufferPointer(start: buffer, count: count))
    }

    /// UTF-8 decode the bytes into a `String` for the lifetime of `body`,
    /// then drop the reference so ARC can collect it. The transient `String`
    /// is **still plaintext on the heap** for the duration of the closure
    /// and possibly a bit longer (ARC isn't synchronous, SwiftUI may capture
    /// the value during diff, etc.) — this API minimizes the dwell time but
    /// doesn't make it zero.
    @discardableResult
    public func withRevealedString<R>(_ body: (String) throws -> R) rethrows -> R {
        try withUnsafeBytes { ptr in
            let chars = ptr.bindMemory(to: UInt8.self)
            let s = String(decoding: chars, as: UTF8.self)
            return try body(s)
        }
    }

    /// Convenience that materializes a `String` without a scoped closure.
    /// Prefer `withRevealedString` whenever the caller controls the use
    /// site — the closure form makes the unsafe lifetime explicit.
    public var revealedString: String {
        withUnsafeBytes { ptr in
            String(decoding: ptr.bindMemory(to: UInt8.self), as: UTF8.self)
        }
    }

    /// Copy the bytes out into a plain `Data` value. Use sparingly — the
    /// returned `Data`'s buffer is **not** zero-on-deinit. Intended for
    /// crossing API boundaries that require `Data` (e.g. `ASPasswordCredential`
    /// returns a String anyway; this is for crypto APIs that take Data).
    public func toData() -> Data {
        withUnsafeBytes { ptr in
            Data(ptr.bindMemory(to: UInt8.self))
        }
    }

    // MARK: - Conformances

    public var description: String {
        // Intentionally **not** including bytes — log-safe.
        "<SecureBytes count=\(count)>"
    }

    public static func == (lhs: SecureBytes, rhs: SecureBytes) -> Bool {
        guard lhs.count == rhs.count else { return false }
        return lhs.withUnsafeBytes { a in
            rhs.withUnsafeBytes { b in
                // Constant-time so equality on secret-derived bytes (e.g.
                // ProtectedString values when diffing entries for save)
                // doesn't leak content by short-circuiting.
                var diff: UInt8 = 0
                for i in 0..<a.count {
                    diff |= a[i] ^ b[i]
                }
                return diff == 0
            }
        }
    }

    public func hash(into hasher: inout Hasher) {
        // Hash by length only — hashing the bytes would put a digest of
        // the secret on stack/heap. SecureBytes shouldn't be a heavily-
        // hashed key type; if it is, the caller should reconsider.
        hasher.combine(count)
    }
}
