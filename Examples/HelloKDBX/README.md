# HelloKDBX

A minimal example of using KDBXKit to open a KeePass `.kdbx` vault,
walk the group tree, and reveal protected fields.

## Run

```sh
cd Examples/HelloKDBX
swift run HelloKDBX
```

Expected output:

```
Opened demo.kdbx
Name:   demo
Cipher: ChaCha20
KDF:    argon2id(... iterations: 5, memory: 67108864, parallelism: 4 ...)

[demo]
  - WiFi at Home
      UserName: admin
      Notes: Router on the shelf
      Password: passphrase42
  [Banking]
    - Chase
        UserName: demo@example.com
        URL: https://chase.com
        Password: hunter2-bank
  [Email]
    - GitHub
        UserName: demo
        URL: https://github.com
        Password: correct-horse-battery-staple
        [totp-secret] = JBSWY3DPEHPK3PXP
```

To use it against your own vault:

```sh
swift run HelloKDBX path/to/your-vault.kdbx
```

(The password is hard-coded as `demo` in `main.swift`. Edit it,
prompt for it on stdin, or load it from your platform keychain
before pointing the example at a real vault.)

## What the example shows

| Concept                 | Where in `main.swift` |
|-------------------------|-----------------------|
| Build an `UnlockData`   | `UnlockData(masterPassword:)` |
| Open a vault            | `KDBXReader.parse(_:unlockData:)` |
| Walk Group → Entry      | `content.database.root.group` then `.groups` / `.entries` |
| Read a regular field    | `entry.strings.first { $0.key == "Title" }?.value.revealedString` |
| Reveal a protected field | `value.withRevealedString { plaintext in ... }` (scoped) |
| List attachments        | `entry.binaries.map(\.key)` |

The `withRevealedString { ... }` pattern is the recommended way to
work with secrets: the cleartext lives only for the duration of the
closure, then KDBXKit's `SecureBytes`-backed storage zeros itself.

## Demo vault

`demo.kdbx` was built with the `kdbx` CLI:

```sh
echo "demo" | swift run kdbx db create demo.kdbx --new-password-stdin
KDBX_PASSWORD=demo swift run kdbx group add demo.kdbx Banking --in /
KDBX_PASSWORD=demo swift run kdbx group add demo.kdbx Email --in /
echo "hunter2-bank" | KDBX_PASSWORD=demo swift run kdbx entry add \
    demo.kdbx Chase --in /Banking \
    --username 'demo@example.com' --url 'https://chase.com' \
    --entry-password-stdin
# ... etc
```

KDF is Argon2id with the default `.balanced` profile (5 iterations,
64 MiB memory, parallelism 4); cipher is ChaCha20; compression is
gzip.

## Next steps

- See `docs/spec/kdbx-container.md` and `docs/spec/kdbx-xml.md` for
  the full format specification.
- See `Sources/KDBXKit/` for the library and `Sources/kdbx-cli/`
  for a real CLI implementation built on the same API.
