// party.ts — a throwaway party for a test: an Ed25519 pair born in the test
// isolate, its party id `ed25519:<base64url of the 32 public bytes>` as the
// peer protocol spells it, and a signer that returns base64url without
// padding, the X-Peer-Signature encoding.

export const b64url = (bytes: Uint8Array): string =>
	btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

export type Party = { id: string; sign: (bytes: Uint8Array | string) => Promise<string> };

export async function newParty(): Promise<Party> {
	const kp = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
	const pub = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
	const enc = new TextEncoder();
	return {
		id: "ed25519:" + b64url(pub),
		sign: async (bytes) => b64url(new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, kp.privateKey, typeof bytes === "string" ? enc.encode(bytes) : bytes))),
	};
}
