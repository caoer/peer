---
version: alpha
name: "Peer reader"
description: "A party member reads the party's messages — received and sent — on a phone or a desktop from one link, and opens encrypted ones in the browser."
colors:
  bg: "oklch(0.975 0.006 75)"
  bg-sunken: "oklch(0.950 0.009 75)"
  bg-raised: "oklch(0.995 0.002 75)"
  fg: "oklch(0.270 0.015 65)"
  fg-muted: "oklch(0.480 0.015 65)"
  fg-subtle: "oklch(0.525 0.012 65)"
  border: "oklch(0.890 0.010 75)"
  border-strong: "oklch(0.620 0.012 70)"
  accent: "oklch(0.450 0.130 255)"
  accent-soft: "oklch(0.930 0.030 255)"
  on-accent: "oklch(0.995 0.002 75)"
  primary: "{colors.accent}"
  status-ok: "oklch(0.520 0.120 150)"
  status-warn: "oklch(0.530 0.130 70)"
  status-err: "oklch(0.530 0.180 28)"
  status-info: "{colors.accent}"
typography:
  display: { fontFamily: "Georgia", fontSize: 20px, fontWeight: 600, lineHeight: 1.25 }
  title: { fontFamily: "system-ui", fontSize: 14px, fontWeight: 600, lineHeight: 1.3 }
  body: { fontFamily: "system-ui", fontSize: 16px, fontWeight: 400, lineHeight: 1.5 }
  label: { fontFamily: "system-ui", fontSize: 12px, fontWeight: 500, lineHeight: 1.3 }
  mono: { fontFamily: "ui-monospace", fontSize: 13px, fontWeight: 400, lineHeight: 1.4 }
rounded: { sm: 4px, md: 8px }
spacing: { 1: 4px, 2: 8px, 3: 12px, 4: 16px, 6: 24px, 8: 32px }
components:
  page: { backgroundColor: "{colors.bg}", textColor: "{colors.fg}", typography: "{typography.body}" }
  page-title: { backgroundColor: "{colors.bg}", textColor: "{colors.fg}", typography: "{typography.display}" }
  row: { backgroundColor: "{colors.bg}", textColor: "{colors.fg}", typography: "{typography.body}" }
  row-own: { backgroundColor: "{colors.bg-sunken}", textColor: "{colors.fg}", typography: "{typography.body}", rounded: "{rounded.md}", padding: 12px }
  row-meta: { backgroundColor: "{colors.bg}", textColor: "{colors.fg-subtle}", typography: "{typography.label}" }
  row-kind: { backgroundColor: "{colors.bg}", textColor: "{colors.fg-muted}", typography: "{typography.label}" }
  id: { backgroundColor: "{colors.bg}", textColor: "{colors.fg-subtle}", typography: "{typography.mono}" }
  panel: { backgroundColor: "{colors.bg-sunken}", textColor: "{colors.fg}", rounded: "{rounded.md}", padding: 12px }
  button-secondary: { backgroundColor: "{colors.bg-raised}", textColor: "{colors.fg}", typography: "{typography.label}", rounded: "{rounded.sm}", height: 32px, padding: 12px }
  input: { backgroundColor: "{colors.bg-raised}", textColor: "{colors.fg}", typography: "{typography.mono}", rounded: "{rounded.sm}", height: 32px }
  input-edge: { backgroundColor: "{colors.border-strong}", width: 1px }
  selection: { backgroundColor: "{colors.accent-soft}", textColor: "{colors.accent}", rounded: "{rounded.sm}" }
  divider: { backgroundColor: "{colors.border}", height: 1px }
  status-ok: { backgroundColor: "{colors.bg}", textColor: "{colors.status-ok}", typography: "{typography.label}" }
  status-warn: { backgroundColor: "{colors.bg}", textColor: "{colors.status-warn}", typography: "{typography.label}" }
  status-err: { backgroundColor: "{colors.bg}", textColor: "{colors.status-err}", typography: "{typography.label}" }
---

## Overview

The reader is `index.html` beside this file: one page, no external code, served at `/` by the peer worker (docs/protocol.md § Reader feed and forward). A party member opens it from the link `peer feed link` printed, on a phone as often as on a desktop, to read what the other party's agents sent and what ours sent, and to open encrypted messages with the key the browser holds. The first screen answers: what came in, from whom, when — and did it open here. Mode: Operate.

Direction: a quiet list in the system sans, newest at the bottom, every state said in a word. Chrome recedes; the message body leads. The page loads no font, image or script, so every value here is a system stack or a colour literal.

## Colors

- `bg` is the paper; `bg-sunken` one step into it (the key panel; a sent message's row); `bg-raised` one step toward the viewer (the input and the import button). All three sit on hue 75 and differ only in lightness.
- `fg`, `fg-muted`, `fg-subtle`: content, secondary (the other side's name, labels), tertiary (times, ids). All three hold 4.5:1 on every surface.
- `accent` names our own side (我方) and the one primary control, the selection, the caret and the focus ring. Nothing else is blue.
- `status-ok` is a message opened in this browser; `status-err` a message that did not open (wrong key, tampered, unreadable); `status-warn` a truncated body and a key problem. Each status colour sits on a word, never on a surface.

### Dark

Dark follows `prefers-color-scheme` through the same variable names, designed from the same hue: raised surfaces lighter than the base, no shadows, status colours lighter and less saturated. A sent message's row takes `bg-raised` in dark (lighter than the base) where it takes `bg-sunken` in light.

| Token | Light (default) | Dark |
|---|---|---|
| bg | oklch(0.975 0.006 75) | oklch(0.200 0.008 70) |
| bg-sunken | oklch(0.950 0.009 75) | oklch(0.170 0.008 70) |
| bg-raised | oklch(0.995 0.002 75) | oklch(0.250 0.009 70) |
| fg | oklch(0.270 0.015 65) | oklch(0.930 0.008 75) |
| fg-muted | oklch(0.480 0.015 65) | oklch(0.720 0.010 75) |
| fg-subtle | oklch(0.525 0.012 65) | oklch(0.650 0.010 75) |
| border | oklch(0.890 0.010 75) | oklch(0.300 0.010 70) |
| border-strong | oklch(0.620 0.012 70) | oklch(0.560 0.012 70) |
| accent | oklch(0.450 0.130 255) | oklch(0.780 0.100 250) |
| accent-soft | oklch(0.930 0.030 255) | oklch(0.300 0.050 250) |
| on-accent | oklch(0.995 0.002 75) | oklch(0.200 0.008 70) |
| status-ok | oklch(0.520 0.120 150) | oklch(0.750 0.110 150) |
| status-warn | oklch(0.530 0.130 70) | oklch(0.800 0.120 80) |
| status-err | oklch(0.530 0.180 28) | oklch(0.720 0.150 28) |

## Typography

- Stacks: serif `Georgia, "Iowan Old Style", "Songti SC", "Noto Serif CJK SC", serif` for the page title alone; sans `system-ui, -apple-system, "Segoe UI", Roboto, "PingFang SC", "Noto Sans CJK SC", sans-serif` for everything read or acted on; mono `ui-monospace, "SF Mono", Menlo, monospace` for ids, keys, ciphertext and a record's raw time.
- Scale 12 / 14 / 16 / 20 px as fixed rem values. `body` 16 px is the message text at every width; `title` 14 px 600 is the sender; `label` 12 px 500 is a kind word, a state word, a details label; `mono` 13 px. Nothing under 12 px.
- Hierarchy at one size comes from weight and tone: sender 600, kind word 500 `fg-muted`, time and id 400 `fg-subtle` with `tabular-nums`. Sentence case; headings `text-wrap: balance`.

## Layout

- One column, `max-width: 44rem`, margins 16 px on a phone and 32 px on desktop. Order: title and connection state → the key panel → the day-grouped list, oldest to newest, scrolled to the newest once the replay lands → the guide, collapsed.
- A message row: a head line (the sender's party name and agent · kind … time; from a host that sends no name, the side word 我方 or 对方 with the counterpart's shortened id in the name's place), the body, a 「详情」 disclosure. Rows are separated by a `divider` hairline; a sent row sits on `row-own` with no border. 12 px inside a row, 16 px between rows, 24 px above a day label.
- Under `(pointer: coarse)` every control and summary grows to 44 px; the input stays 16 px so iOS does not zoom.

## Elevation & Depth

- One depth strategy: surface lightness steps plus the `border` hairline. No shadows anywhere; no floating layer exists on this page.
- Focus ring: `outline: 2px solid` the accent, `outline-offset: 2px`, on `:focus-visible` only.

## Shapes

- `sm` on the input and the button; `md` on the key panel and a sent row. No icons: every state is a word.

## Components

- Message row states: plain · 已在本机解密 (`status-ok` word under the body) · 已锁定 (`fg-muted` line in place of the body) · 这把钥匙打不开 / 无法读取的加密消息 (`status-err` line in place of the body) · 已截断 (`status-warn` word in the head). A file row shows name 600, size and type; a card exchange is a `fg-muted` event line.
- 「详情」 opens two groups: 明文部分 (编号, 类型, 发出方, 接收方, 对方主体 — the counterpart's full party id — 时间; what every host in the path sees) and, for an encrypted message, 加密部分 (加密方式, 收件钥匙 with 本浏览器的钥匙 marked, 密文 with its size and bytes).
- The key panel: one state line, one note line (`status-warn`), the advanced import as a native `<details>`.
- Motion: none. A new message is appended in place; the list follows the newest only when the reader was already at the end.

## Do's and Don'ts

- Do say every state in a word beside its colour; never colour alone.
- Do keep the technical record one tap away, never on the face of a message.
- Don't load a font, an image or a script; the page is one file by contract.
- Don't add a colour, size or radius this file does not list; add it here first.
