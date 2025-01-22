import type { BinaryLike, KeyObject } from "crypto";
import { createHmac, timingSafeEqual } from "crypto";

export async function fetchWithHmac(key: BinaryLike | KeyObject, input: string | URL | Request, init?: RequestInit): Promise<Response> {
	const request = new Request(input, init);

	request.headers.set("X-Hmac-Timestamp", Date.now().toString(10));
	request.headers.set("X-Hmac-Signature", await getSignature(request, key, true));

	return fetch(request);
}

export async function validateHmac(key: BinaryLike | KeyObject, request: Request): Promise<boolean> {
	const signature = request.headers.get("X-Hmac-Signature");
	const timestamp = request.headers.get("X-Hmac-Timestamp");

	if (!signature || !timestamp) {
		return false;
	}

	const timestampParsed = Number.parseInt(timestamp, 10);

	return (
		!Number.isNaN(timestampParsed) &&
		Math.abs(Date.now() - timestampParsed) <= 300000 &&
		timingSafeEqual(Buffer.from(signature, "base64"), await getSignature(request, key))
	);
}

async function getSignature(request: Request, key: BinaryLike | KeyObject, base64?: false): Promise<Buffer>;
async function getSignature(request: Request, key: BinaryLike | KeyObject, base64: true): Promise<string>;
async function getSignature(request: Request, key: BinaryLike | KeyObject, base64?: boolean): Promise<Buffer | string> {
	const hmac = createHmac("sha256", key);

	hmac.update(
		request.method + "\r\n" +
		request.url + "\r\n" +
		(request.headers.get("Content-Type") ?? "") + "\r\n" +
		(request.headers.get("X-Hmac-Timestamp") ?? "") + "\r\n"
	);

	if (request.body != null) {
		hmac.update(new Uint8Array(await request.clone().arrayBuffer()));
	}

	return base64 ? hmac.digest("base64") : hmac.digest();
}
