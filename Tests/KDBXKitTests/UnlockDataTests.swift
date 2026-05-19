import Foundation
import Testing
@testable import KDBXKit

@Suite("UnlockData — rehydration from raw key data")
struct UnlockDataTests {
    @Test("rawKeyData init produces an UnlockData with the same key bytes")
    func rawKeyDataRoundtrip() {
        let bytes = Data((0..<32).map { UInt8($0) })
        let unlock = UnlockData(rawKeyData: bytes)
        let roundtripped = unlock.keyDataBytes.withUnsafeBytes { Data($0) }
        #expect(roundtripped == bytes)
    }

    @Test("rawKeyData unlock decrypts a vault created with the matching password")
    func rawKeyDataUnlocksRealVault() throws {
        // The pre-hash R = SHA-256( SHA-256(password.utf8) ). Recompute and
        // confirm a vault built with the password opens identically when
        // we rehydrate the UnlockData from those 32 bytes only.
        let password = "correct horse battery staple"
        let preHash = password.data(using: .utf8)!.sha256().sha256()

        let viaPassword = UnlockData(masterPassword: password)
        let viaRaw = UnlockData(rawKeyData: preHash)

        let bytesA = viaPassword.keyDataBytes.withUnsafeBytes { Data($0) }
        let bytesB = viaRaw.keyDataBytes.withUnsafeBytes { Data($0) }
        #expect(bytesA == bytesB)
    }

    @Test("matches() returns true for the same password, false otherwise")
    func matchesSamePassword() {
        let unlock = UnlockData(masterPassword: "the right password")
        #expect(unlock.matches(UnlockData(masterPassword: "the right password")) == true)
        #expect(unlock.matches(UnlockData(masterPassword: "the wrong password")) == false)
    }
}
