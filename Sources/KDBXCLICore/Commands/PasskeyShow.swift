//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import ArgumentParser
import Foundation
import KDBXKit

extension Passkey {
    struct Show: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "show",
            abstract: "Show one passkey's metadata. The private key is never printed."
        )

        // Declared before `commonOptions` so the relying party is the first
        // positional and the file path (from CommonOptions) is the second:
        //   kdbx passkey show <relying-party> <file>
        @Argument(help: ArgumentHelp("Relying party to look up.", valueName: "relying-party"))
        var relyingParty: String

        @OptionGroup()
        var commonOptions: CommonOptions

        mutating func run() throws {
            let unlockData = try commonOptions.credentials.resolve(requireUnlock: true)
            guard
                case let .success(content, _) = try read(from: commonOptions.filepath, unlockData: unlockData)
            else {
                throw AppError.wrongCredentials
            }

            var match: KDBX.Entry?
            content.database.visitEntries(in: content.database.root.group) { entry in
                guard match == nil else { return }
                if entry.isPasskey, entry.passkeyRelyingParty == relyingParty {
                    match = entry
                }
            }

            guard let entry = match else {
                throw ValidationError("No passkey found for relying party '\(relyingParty)'")
            }

            // Metadata only. The private key PEM is held in SecureBytes and
            // is deliberately never read or printed here.
            print("Relying party: \(entry.passkeyRelyingParty ?? "")")
            print("Username: \(entry.passkeyUsername ?? "")")
            print("Credential ID: \(entry.passkeyCredentialIDBase64URL ?? "")")
            print("User handle: \(entry.passkeyUserHandleBase64URL ?? "")")
            print("Private key: <protected — not shown>")
        }
    }
}
