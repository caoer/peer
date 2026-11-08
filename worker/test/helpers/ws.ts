// ws.ts — one accepted client socket for a test: text frames parsed as they
// arrive, a wait for the next frame of a type, a check that none arrived, and
// the close. This one has no binary lane.

import { expect } from "vitest";
import { sleep } from "./sleep";

// How long a frame that SHOULD arrive is waited for. Only a failing test
// reaches it (bus.spec.ts: a loaded CI agent has taken past two seconds).
export const FRAME_WAIT_MS = 30_000;

export type Frame = Record<string, any>;

export const wrap = async (res: Response) => {
	expect(res.status, res.status === 101 ? "" : await res.clone().text()).toBe(101);
	const ws = res.webSocket!;
	const frames: Frame[] = [];
	const raw: string[] = [];
	let onClose!: (v: { code: number; reason: string }) => void;
	const closed = new Promise<{ code: number; reason: string }>((r) => (onClose = r));
	ws.addEventListener("message", (e) => {
		if (typeof e.data !== "string") throw new Error("a text frame was expected");
		raw.push(e.data);
		frames.push(JSON.parse(e.data));
	});
	ws.addEventListener("close", (e) => onClose({ code: e.code, reason: e.reason }));
	ws.accept();
	// The first frame of `type` that `where` accepts, taken off the queue.
	const next = async (type: string, where: (m: Frame) => boolean = () => true, ms = FRAME_WAIT_MS): Promise<Frame> => {
		const until = Date.now() + ms;
		for (;;) {
			const i = frames.findIndex((m) => m.type === type && where(m));
			if (i >= 0) return frames.splice(i, 1)[0]!;
			if (Date.now() >= until) break;
			await sleep(10);
		}
		throw new Error(`no "${type}" frame; saw ${JSON.stringify(frames).slice(0, 2000)}`);
	};
	// Nothing of `type` (any type when omitted) arrives within `ms`.
	const none = async (type?: string, ms = 200) => {
		await sleep(ms);
		expect(frames.filter((m) => type === undefined || m.type === type)).toEqual([]);
	};
	// The next `count` frames of any type, in arrival order.
	const take = async (count: number, ms = FRAME_WAIT_MS): Promise<Frame[]> => {
		const until = Date.now() + ms;
		while (frames.length < count && Date.now() < until) await sleep(10);
		expect(frames.length, `waiting for ${count} frames; saw ${JSON.stringify(frames).slice(0, 2000)}`).toBeGreaterThanOrEqual(count);
		return frames.splice(0, count);
	};
	return { ws, frames, raw, next, none, take, closed, send: (s: string) => ws.send(s), close: () => ws.close(1000, "bye") };
};

export type Wrapped = Awaited<ReturnType<typeof wrap>>;
