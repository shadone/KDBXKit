//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

/// A streaming byte consumer. The writer side of the pipeline:
/// callers push bytes; the implementation transforms / forwards them
/// to the next stage. `finalize()` runs once and emits any tail bytes
/// the implementation was holding back.
///
/// Reference type by design — each layer holds a strong reference to
/// the next downstream layer, so the pipeline forms a chain of
/// classes. State (encryptor counters, buffered bytes, etc.) lives on
/// each layer's instance.
///
/// Internal — backs `KDBXWriter.streamingWrite`. Public callers don't
/// see this protocol.
protocol StreamingByteConsumer: AnyObject {
    func consume(_ chunk: Data) throws
    func finalize() throws
}
