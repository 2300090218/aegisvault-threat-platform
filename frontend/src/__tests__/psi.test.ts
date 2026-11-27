import { describe, expect, it } from "vitest";
import {
  blindClientItems,
  compressPoint,
  decompressPoint,
  generateClientScalar,
  hashToCurve,
  resolvePsiMatches,
  scalarMult,
} from "../utils/psi";

describe("Client-side NIST P-256 ECDH-PSI", () => {
  it("computes commutative blinded curve points and finds exact intersection", async () => {
    const serverHashes = [
      "d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5",
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ];
    const clientCandidates = [
      "1111111111111111111111111111111111111111111111111111111111111111",
      "d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5",
    ];

    const clientScalar = generateClientScalar();
    const serverScalar = 9876543210987654321n;

    const blindedClient = await blindClientItems(clientCandidates, clientScalar);
    expect(blindedClient).toHaveLength(2);

    // Simulate server step: compute H_tag(b * A_i) and b * H(y_j)
    const doubleBlindedClientHashes: string[] = [];
    for (const ptHex of blindedClient) {
      const dbl = scalarMult(serverScalar, decompressPoint(ptHex));
      const enc = new TextEncoder().encode("PSI-TAG:" + compressPoint(dbl));
      const digest = new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", enc));
      const hex = Array.from(digest)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
      doubleBlindedClientHashes.push(hex);
    }

    const serverBlindedPoints: string[] = [];
    for (const y of serverHashes) {
      const pt = await hashToCurve(y);
      serverBlindedPoints.push(compressPoint(scalarMult(serverScalar, pt)));
    }

    const matches = await resolvePsiMatches({
      candidateItems: clientCandidates,
      scalar: clientScalar,
      doubleBlindedClientHashes,
      serverBlindedPoints,
    });

    expect(matches).toEqual(["d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5"]);
  });
});
