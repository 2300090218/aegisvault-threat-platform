/**
 * Client-side NIST P-256 (secp256r1) ECDH-PSI blinding & intersection matcher.
 * Mirrors backend `app/privacy/psi.py` exactly using BigInt modular arithmetic + WebCrypto SHA-256.
 */

const P256_P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const P256_A = (P256_P - 3n) % P256_P;
const P256_B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;
const P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const SQRT_EXP = (P256_P + 1n) >> 2n;
const LEGENDRE_EXP = (P256_P - 1n) >> 1n;

export type CurvePoint = { x: bigint; y: bigint } | null;

function mod(a: bigint, m: bigint): bigint {
  const r = a % m;
  return r >= 0n ? r : r + m;
}

function modPow(base: bigint, exp: bigint, m: bigint): bigint {
  let result = 1n;
  let b = mod(base, m);
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % m;
    b = (b * b) % m;
    e >>= 1n;
  }
  return result;
}

function modInv(a: bigint, m: bigint): bigint {
  return modPow(a, m - 2n, m);
}

export function pointAdd(p1: CurvePoint, p2: CurvePoint): CurvePoint {
  if (!p1) return p2;
  if (!p2) return p1;
  const { x: x1, y: y1 } = p1;
  const { x: x2, y: y2 } = p2;
  if (x1 === x2) {
    if (mod(y1 + y2, P256_P) === 0n) return null;
    const lam = mod((3n * x1 * x1 + P256_A) * modInv(2n * y1, P256_P), P256_P);
    const x3 = mod(lam * lam - x1 - x2, P256_P);
    const y3 = mod(lam * (x1 - x3) - y1, P256_P);
    return { x: x3, y: y3 };
  }
  const lam = mod((y2 - y1) * modInv(x2 - x1, P256_P), P256_P);
  const x3 = mod(lam * lam - x1 - x2, P256_P);
  const y3 = mod(lam * (x1 - x3) - y1, P256_P);
  return { x: x3, y: y3 };
}

export function scalarMult(k: bigint, pt: CurvePoint): CurvePoint {
  let scalar = mod(k, P256_N);
  if (scalar === 0n || !pt) return null;
  let res: CurvePoint = null;
  let addend: CurvePoint = pt;
  while (scalar > 0n) {
    if (scalar & 1n) res = pointAdd(res, addend);
    addend = pointAdd(addend, addend);
    scalar >>= 1n;
  }
  return res;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  return BigInt("0x" + bytesToHex(bytes));
}

async function sha256Bytes(data: Uint8Array): Promise<Uint8Array> {
  const copy = new Uint8Array(data.byteLength);
  copy.set(data);
  const buf = await globalThis.crypto.subtle.digest("SHA-256", copy);
  return new Uint8Array(buf);
}

export function compressPoint(pt: CurvePoint): string {
  if (!pt) throw new Error("Cannot compress point at infinity");
  const prefix = (pt.y & 1n) === 0n ? "02" : "03";
  return prefix + pt.x.toString(16).padStart(64, "0");
}

export function decompressPoint(hexStr: string): { x: bigint; y: bigint } {
  const cleaned = hexStr.trim().toLowerCase();
  if (cleaned.length !== 66 || (cleaned.slice(0, 2) !== "02" && cleaned.slice(0, 2) !== "03")) {
    throw new Error("Invalid compressed P-256 point");
  }
  const parity = cleaned.slice(0, 2) === "03" ? 1n : 0n;
  const x = BigInt("0x" + cleaned.slice(2));
  const rhs = mod(x * x * x + P256_A * x + P256_B, P256_P);
  if (modPow(rhs, LEGENDRE_EXP, P256_P) !== 1n) {
    throw new Error("Point does not lie on P-256");
  }
  let y = modPow(rhs, SQRT_EXP, P256_P);
  if ((y & 1n) !== parity) {
    y = P256_P - y;
  }
  return { x, y };
}

export async function hashToCurve(item: string): Promise<{ x: bigint; y: bigint }> {
  const encoder = new TextEncoder();
  const prefix = encoder.encode("PSI-P256-H2C:");
  const norm = encoder.encode(item.trim().toLowerCase());
  for (let counter = 0; counter < 256; counter++) {
    const buf = new Uint8Array(prefix.length + norm.length + 1);
    buf.set(prefix, 0);
    buf.set(norm, prefix.length);
    buf[prefix.length + norm.length] = counter;
    const digest = await sha256Bytes(buf);
    const x = mod(bytesToBigInt(digest), P256_P);
    const rhs = mod(x * x * x + P256_A * x + P256_B, P256_P);
    if (modPow(rhs, LEGENDRE_EXP, P256_P) === 1n) {
      let y = modPow(rhs, SQRT_EXP, P256_P);
      if ((y & 1n) === 1n) {
        y = P256_P - y;
      }
      return { x, y };
    }
  }
  throw new Error("Failed to map item to P-256");
}

async function tagPoint(pt: CurvePoint): Promise<string> {
  const encoded = new TextEncoder().encode("PSI-TAG:" + compressPoint(pt));
  return bytesToHex(await sha256Bytes(encoded));
}

export function generateClientScalar(): bigint {
  const randomBytes = new Uint8Array(32);
  globalThis.crypto.getRandomValues(randomBytes);
  return mod(bytesToBigInt(randomBytes), P256_N - 1n) + 1n;
}

export async function blindClientItems(items: string[], scalar: bigint): Promise<string[]> {
  const out: string[] = [];
  for (const item of items) {
    const pt = await hashToCurve(item);
    out.push(compressPoint(scalarMult(scalar, pt)));
  }
  return out;
}

export async function resolvePsiMatches(params: {
  candidateItems: string[];
  scalar: bigint;
  doubleBlindedClientHashes: string[];
  serverBlindedPoints: string[];
}): Promise<string[]> {
  const serverTags = new Set<string>();
  for (const ptHex of params.serverBlindedPoints) {
    const pt = decompressPoint(ptHex);
    const unblinded = scalarMult(params.scalar, pt);
    serverTags.add(await tagPoint(unblinded));
  }
  return params.candidateItems.filter((_, idx) => serverTags.has(params.doubleBlindedClientHashes[idx]));
}
