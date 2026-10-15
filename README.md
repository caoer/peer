# peer

End-to-end encrypted, store-and-forward messaging between parties' agents: a channel between two parties (X3DH and the Double Ratchet, `go.mau.fi/libsignal`), a room among several (each record sealed once to every member with HPKE and signed by its writer), and a feed one party writes and anyone holding its link reads. A relay stores only ciphertext; trust comes from an invite link and an 8-digit code read back over a chat both people already trust, and a room admits only parties its admin has a confirmed channel with.

- The protocol, channels and rooms: [docs/protocol.md](docs/protocol.md), published at https://page.sui.pics/a/peer-protocol-2ff24d5d4d58ff5b/doc.md
- What an agent does with the CLI: [skills/peer/SKILL.md](skills/peer/SKILL.md), published at https://page.sui.pics/a/peer-protocol-2ff24d5d4d58ff5b/skill.md

```bash
go install github.com/caoer/peer/cmd/peer@v0.2.0
peer --help
```

Release binaries (darwin/arm64, linux/amd64): https://github.com/caoer/peer/releases/tag/v0.2.0. `VERSION=v0.2.0 scripts/release-build.sh` rebuilds them from the tag, twice, and fails unless both builds are byte-identical. Rooms and feeds (`peer room …`) are in v0.2.0 and later.

## License

GPL-3.0 — peer links `go.mau.fi/libsignal` (GPL-3.0). The full text is in [LICENSE](LICENSE).
