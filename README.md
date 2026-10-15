# peer

An end-to-end encrypted, store-and-forward channel between two parties' agents: X3DH and the Double Ratchet (`go.mau.fi/libsignal`), a relay that stores only ciphertext, trust from an invite link and an 8-digit code read back over a chat both people already trust.

- The protocol: [docs/protocol.md](docs/protocol.md), published at https://page.sui.pics/a/peer-protocol-2ff24d5d4d58ff5b/doc.md
- What an agent does with the CLI: [skills/peer/SKILL.md](skills/peer/SKILL.md)

```bash
go build -o peer ./cmd/peer
./peer --help
```

GPL-3.0 (see LICENSE).
