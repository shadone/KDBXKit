//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import ArgumentParser
import Foundation
import KDBXKit

extension Passkey {
    struct Ls: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "ls",
            abstract: "List passkeys as relying party + username, one per line."
        )

        @OptionGroup()
        var commonOptions: CommonOptions

        mutating func run() throws {
            let unlockData = try commonOptions.credentials.resolve(requireUnlock: true)
            guard
                case let .success(content, _) = try read(from: commonOptions.filepath, unlockData: unlockData)
            else {
                throw AppError.wrongCredentials
            }

            // Collect into a local array so the visitor closure stays pure.
            // Print only the relying party and username — credential ID,
            // user handle, and the private key are never surfaced by `ls`.
            var lines: [String] = []
            content.database.visitEntries(in: content.database.root.group) { entry in
                guard entry.isPasskey, let relyingParty = entry.passkeyRelyingParty else { return }
                let username = entry.passkeyUsername ?? ""
                lines.append("\(relyingParty)\t\(username)")
            }

            for line in lines {
                print(line)
            }
        }
    }
}
