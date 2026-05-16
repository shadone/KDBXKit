//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import KDBXKit

/// Header fields are immutable (`let`) in KDBXKit. Mutating commands in the
/// CLI build replacement values via these copy helpers so call sites stay
/// readable. Each helper preserves every other field.
extension Header {
    func with(kdfParameters: KDFParameters) -> Header {
        Header(
            formatVersion: formatVersion,
            encryptionAlgorithm: encryptionAlgorithm,
            compressionAlgorithm: compressionAlgorithm,
            masterSalt: masterSalt,
            encryptionNonce: encryptionNonce,
            kdfParameters: kdfParameters,
            publicCustomData: publicCustomData
        )
    }

    func with(encryptionAlgorithm: EncryptionAlgorithm) -> Header {
        Header(
            formatVersion: formatVersion,
            encryptionAlgorithm: encryptionAlgorithm,
            compressionAlgorithm: compressionAlgorithm,
            masterSalt: masterSalt,
            encryptionNonce: encryptionNonce,
            kdfParameters: kdfParameters,
            publicCustomData: publicCustomData
        )
    }

    func with(compressionAlgorithm: CompressionAlgorithm) -> Header {
        Header(
            formatVersion: formatVersion,
            encryptionAlgorithm: encryptionAlgorithm,
            compressionAlgorithm: compressionAlgorithm,
            masterSalt: masterSalt,
            encryptionNonce: encryptionNonce,
            kdfParameters: kdfParameters,
            publicCustomData: publicCustomData
        )
    }
}
