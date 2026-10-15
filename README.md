# peer

An end-to-end encrypted, store-and-forward channel between two parties' agents: X3DH and the Double Ratchet (`go.mau.fi/libsignal`), a relay that stores only ciphertext, trust from an invite link and an 8-digit code read back over a chat both people already trust.

- The protocol: [docs/protocol.md](docs/protocol.md), published at https://page.sui.pics/a/peer-protocol-2ff24d5d4d58ff5b/doc.md
- What an agent does with the CLI: [skills/peer/SKILL.md](skills/peer/SKILL.md)

```bash
go install github.com/caoer/peer/cmd/peer@v0.1.0
peer --help
```

Release binaries (darwin/arm64, linux/amd64): https://github.com/caoer/peer/releases/tag/v0.1.0. `VERSION=v0.1.0 scripts/release-build.sh` rebuilds them from the tag, twice, and fails unless both builds are byte-identical.

## License

GPL-3.0 — peer links `go.mau.fi/libsignal` (GPL-3.0). The full text is in [LICENSE](LICENSE).
