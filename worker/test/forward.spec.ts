// POST /forward: the bearer, the worker-side targets, the Telegram line, and
// the answer when Telegram fails. handleForward runs in this isolate, so
// globalThis.fetch stubbed here is the fetch it calls.

import { SELF } from "cloudflare:test";
import { describe, it, expect, vi, afterEach } from "vitest";
import { CUT_MARK, ENCRYPTED_LINE, LINE_BODY_MAX, READER_URL, handleForward, lineOf } from "../src/forward";

const SECRET = "fwd_" + "9".repeat(39);
const YUJING = "ed25519:" + "Y".repeat(43);
const ZT = "ed25519:" + "T".repeat(43);
const OTHER = "ed25519:" + "Z".repeat(43);
const ENV = {
	FORWARD_SECRET: SECRET,
	FORWARD_TARGETS: JSON.stringify({ [YUJING]: { chat: -1001234567890, topic: 17624 } }),
	TG_BOT_TOKEN: "123:abc",
};
const AT = "2026-11-08T15:00:00Z";
// A record's from and to are protocol addresses; the host names the sender
// beside the record (`from` on the body), as its roster or config spells it.
const rec = (data: Record<string, unknown>) => ({ schema: "peer-timeline@1", data: { id: "m1", dir: "in", kind: "text", from: `${YUJING}/agent`, to: `${ZT}/zt`, at: AT, ...data } });
const post = (data: Record<string, unknown>, from = "yujing") => ({ peer: YUJING, from, record: rec(data) });
const req = (body: unknown, token = SECRET) =>
	new Request("https://peer.0xtau.com/forward", {
		method: "POST",
		headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
		body: JSON.stringify(body),
	});

const telegram = (status = 200, message_id = 42) =>
	vi.spyOn(globalThis, "fetch").mockImplementation(async () =>
		new Response(JSON.stringify(status === 200 ? { ok: true, result: { message_id } } : { ok: false }), { status }),
	);
const sentText = (spy: ReturnType<typeof telegram>) => JSON.parse(spy.mock.calls[0]![1]!.body as string);

afterEach(() => vi.restoreAllMocks());

describe("POST /forward", () => {
	it("sends a received message to its party's topic, headed by the sender's name, and answers the message id", async () => {
		const spy = telegram();
		const res = await handleForward(req(post({ body: "你好" })), ENV);
		expect(res.status).toBe(200);
		expect(await res.json()).toEqual({ message_id: 42 });
		expect(spy).toHaveBeenCalledTimes(1);
		expect(String(spy.mock.calls[0]![0])).toBe("https://api.telegram.org/bot123:abc/sendMessage");
		const sent = sentText(spy);
		expect(sent).toMatchObject({ chat_id: -1001234567890, message_thread_id: 17624 });
		expect(sent.text).toBe(`yujing · text · ${AT}\n你好\n${READER_URL}`);
	});

	it("names our party on a sent record", async () => {
		const spy = telegram();
		await handleForward(req(post({ dir: "out", from: `${ZT}/zt`, to: YUJING, body: "收到" }, "zt")), ENV);
		expect(sentText(spy).text).toBe(`zt · text · ${AT}\n收到\n${READER_URL}`);
	});

	it("names the sender by the record's address when the host sends no name", async () => {
		const spy = telegram();
		await handleForward(req({ peer: YUJING, record: rec({ body: "你好" }) }), ENV);
		expect(sentText(spy).text).toBe(`${YUJING}/agent · text · ${AT}\n你好\n${READER_URL}`);
	});

	it("cuts a 3,600-character body at 3,500 and marks the cut", async () => {
		const spy = telegram();
		await handleForward(req(post({ body: "字".repeat(3_600) })), ENV);
		expect(sentText(spy).text).toBe(`yujing · text · ${AT}\n${"字".repeat(LINE_BODY_MAX)}\n${CUT_MARK}\n${READER_URL}`);
	});

	it("carries no body of an encrypted record", async () => {
		const spy = telegram();
		await handleForward(req(post({ body: "peer-e2e-v1.sealed", e2e: true })), ENV);
		expect(sentText(spy).text).toBe(`yujing · text · ${AT}\n${ENCRYPTED_LINE}\n${READER_URL}`);
	});

	it("answers 204 and sends nothing for a party outside FORWARD_TARGETS", async () => {
		const spy = telegram();
		const res = await handleForward(req({ peer: OTHER, record: rec({ body: "x" }) }), ENV);
		expect(res.status).toBe(204);
		expect(spy).not.toHaveBeenCalled();
	});

	it("answers 502 when Telegram fails", async () => {
		telegram(500);
		const res = await handleForward(req({ peer: YUJING, record: rec({ body: "x" }) }), ENV);
		expect(res.status).toBe(502);
		expect(await res.json()).toMatchObject({ code: "telegram_failed" });
	});

	it("refuses a wrong or missing bearer and a body that is not one record", async () => {
		const spy = telegram();
		expect((await handleForward(req({ peer: YUJING, record: rec({}) }, "fwd_wrong"), ENV)).status).toBe(401);
		expect((await handleForward(req({ peer: YUJING, record: rec({}) }), { ...ENV, FORWARD_SECRET: undefined })).status).toBe(401);
		expect((await handleForward(req({ peer: YUJING, record: { schema: "other", data: {} } }), ENV)).status).toBe(400);
		expect((await handleForward(req({ peer: YUJING, from: 7, record: rec({}) }), ENV)).status).toBe(400);
		expect(spy).not.toHaveBeenCalled();
	});

	it("is routed at /forward, and the Worker without secrets refuses it", async () => {
		const res = await SELF.fetch("https://peer.0xtau.com/forward", { method: "POST", headers: { authorization: `Bearer ${SECRET}` }, body: "{}" });
		expect(res.status).toBe(401);
	});

	it("puts a doc's descriptor on the line as JSON", () => {
		expect(lineOf({ from: "yujing", kind: "doc", at: AT, body: { name: "a.pdf", size: 3 } })).toBe(`yujing · doc · ${AT}\n{"name":"a.pdf","size":3}\n${READER_URL}`);
	});
});
