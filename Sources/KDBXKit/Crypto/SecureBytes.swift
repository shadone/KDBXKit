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
/// 1. Sub-allocates its bytes from a shared, page-locked `SecureArena`
///    (large secrets get a dedicated arena). Many secrets share one
///    `mlock`'d region, so a 12-byte password no longer wires a whole
///    16 KiB page — see `SecureArena` for why that amplification
///    matters on memory-capped hosts like the iOS AutoFill extension.
/// 2. The arena's pages are `mlock`'d so secrets can't be paged out to
///    disk (best-effort — `RLIMIT_MEMLOCK` can refuse and we proceed
///    anyway; a non-pinned page still holds the bytes, it just isn't
///    protected against swap).
/// 3. **Zeroes its slice** when the last reference releases — via
///    `memset_s` on Apple/BSD or `explicit_bzero` on Linux, functions
///    the compiler is forbidden from optimizing away. The arena itself
///    is `munlock`'d and freed (by ARC) once its last secret is gone.
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
    /// The `mlock`'d arena our bytes live in (`nil` for an empty buffer).
    /// Held strong so the arena's wired pages outlive this slice — ARC
    /// `munlock`s and frees the arena when its last secret is released.
    private let arena: SecureArena?
    /// Pointer to our slice within ``arena`` (`nil` for an empty buffer).
    private let dataPtr: UnsafeMutableRawPointer?
    /// Logical byte count exposed to callers.
    public let count: Int

    // MARK: - Initialisers

    /// Build a SecureBytes from any byte sequence. The source is copied into
    /// the page-locked arena slice; the source's own backing memory is
    /// untouched (the caller is responsible for handling that source — if it
    /// was a `Data`/`[UInt8]`, the original bytes are still reachable through
    /// that reference until ARC collects them).
    public convenience init(_ bytes: some Sequence<UInt8>) {
        var array = Array(bytes)
        defer {
            array.withUnsafeMutableBytes { buffer in
                if let base = buffer.baseAddress {
                    secureZero(base, buffer.count)
                }
            }
        }
        self.init(count: array.count) { destination in
            array.withUnsafeBytes { destination.copyMemory(from: $0) }
        }
    }

    private init(count: Int, fill: (UnsafeMutableRawBufferPointer) -> Void) {
        self.count = count
        guard count > 0 else {
            arena = nil
            dataPtr = nil
            return
        }
        let (arena, pointer) = secureBytesArenaAllocator.allocate(count)
        self.arena = arena
        dataPtr = pointer
        fill(UnsafeMutableRawBufferPointer(start: pointer, count: count))
    }

    /// Copy borrowed bytes directly into the zero-on-release arena.
    public convenience init(copying bytes: UnsafeRawBufferPointer) {
        self.init(count: bytes.count) { $0.copyMemory(from: bytes) }
    }

    /// Copy Data directly, without an intermediate plaintext Array.
    /// The source Data remains the caller's responsibility.
    public convenience init(_ data: Data) {
        self.init(count: data.count) { destination in
            data.withUnsafeBytes { destination.copyMemory(from: $0) }
        }
    }

    /// Copy UTF-8 into protected memory without an intermediate Array.
    /// The source String cannot be erased and remains the caller's responsibility.
    public convenience init(utf8 string: String) {
        self.init(count: string.utf8.count) { destination in
            for (index, byte) in string.utf8.enumerated() {
                destination[index] = byte
            }
        }
    }

    /// Build an empty SecureBytes.
    public static var empty: SecureBytes {
        SecureBytes([] as [UInt8])
    }

    /// Whether the buffer carries any bytes. Cheap convenience over
    /// `count == 0`; mirrors the standard-library shape of
    /// `Collection.isEmpty` so callers (and SwiftFormat's `isEmpty`
    /// rule) can reach for the natural form.
    public var isEmpty: Bool {
        count == 0
    }

    deinit {
        // Zero our slice promptly, with a function the compiler can't
        // optimize away (`secureZero` → `memset_s` / `explicit_bzero`).
        // The `arena` reference is released only after this returns, so
        // its pages stay valid (and wired) across the zero; the arena is
        // `munlock`'d and freed by ARC once its last secret is gone.
        if let dataPtr {
            secureZero(dataPtr, count)
        }
    }

    // MARK: - Read access

    /// Lend the underlying bytes for the lifetime of `body`. The pointer is
    /// invalidated when `body` returns — do not let it escape.
    @discardableResult
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        // `dataPtr` is nil only when count == 0, where a nil-start /
        // zero-count buffer is well-formed and never dereferenced.
        try body(UnsafeRawBufferPointer(start: dataPtr, count: count))
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
