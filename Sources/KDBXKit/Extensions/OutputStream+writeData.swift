//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

extension OutputStream {
    enum StreamError: Error {
        case streamError((any Swift.Error)?)
        /// When writing to a fixed length stream, there is no place to write.
        case unexpectedEOF
    }

    func write(data: Data) throws(StreamError) {
        // https://forums.swift.org/t/extension-write-to-outputstream/42817/5
        var remaining = data[...]
        while !remaining.isEmpty {
            let bytesWritten = remaining.withUnsafeBytes { buf in
                // The force unwrap is safe because we know that `remaining` is
                // not empty. The `assumingMemoryBound(to:)` is there just to
                // make Swift’s type checker happy. This would be unnecessary if
                // `write(_:maxLength:)` were (as it should be IMO) declared
                // using `const void *` rather than `const uint8_t *`.
                self.write(
                    buf.baseAddress!.assumingMemoryBound(to: UInt8.self),
                    maxLength: buf.count
                )
            }

            guard bytesWritten >= 0 else {
                if bytesWritten == -1 {
                    throw .streamError(streamError)
                }
                if bytesWritten == 0 {
                    throw .unexpectedEOF
                }
                preconditionFailure("OutputStream: got negative bytes written: \(bytesWritten)")
            }

            remaining = remaining.dropFirst(bytesWritten)
        }
    }
}
