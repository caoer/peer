---
created: 2026-10-14T20:24:00-04:00
session: 14-09-agent-protocol-design
type: seats
about: ZT's party's seat map for peer serve (UCC design v2 § 5, grammar formats/v2) — label → seat | human [[relay seat]] | service URL, with the kinds each accepts
---
# peers/seats.md — ZT's party

The map `peer serve` reads on every fleet host: the agent id a peer addresses (`<party>/<label>`), the seat whose session's `inbox/` receives it, and the kinds it accepts. Grammar: `13-16-ucc-rearchitecture/decisions/peers-seats-grammar.md`. A row outside the grammar makes the whole map invalid and serve refuses to open.

| label | to | accepts | rooms |
|---|---|---|---|
| zt | human [[year=2026/month=09/29-12-super-advisor/rosters/advisor-super]] | text question answer |
| sa | [[year=2026/month=09/29-12-super-advisor/rosters/advisor-super]] | text task question answer doc file ack |
| liaison | [[year=2026/month=09/29-12-super-advisor/rosters/leader-andrew-agent-link]] | text task question answer doc file ack |
| cli | [[year=2026/month=10/14-09-agent-protocol-design/rosters/worker-cli]] | text task question answer ack |
| assistant | [[year=2026/month=10/17-21-agent-rooms-bots/rosters/worker-room-agent]] | text question answer ack | agents-room c9b3b02f982e076e553b59764bbf2fa8 |
| install | [[year=2026/month=10/03-16-collector-rust-rewrite/rosters/leader-install-page]] | text question answer ack |
| cto | [[year=2026/month=11/20-00-ori-jesse-link/rosters/worker-agent-ori]] | text task question answer ack |
| chan-rachel | [[year=2026/month=10/11-15-chan-rachel-network/rosters/advisor-chan-rachel-network]] | text task question answer ack |
| ml-engineer | [[year=2026/month=10/11-15-chan-rachel-network/rosters/worker-ml-engineer]] | text task question answer ack |
