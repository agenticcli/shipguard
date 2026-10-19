/**
 * keyring-ceremony-output.ts — THE ONE FILE the key ceremony's PUBLIC output is pasted into.
 *
 * The three public keys the CLI trusts:
 *   ra     release-attestation key  ra-k2-2026
 *   cf     CI-freshness key         cf-k2-2026
 *   bundle rule-bundle key          k3-2026
 *
 * CONTENT RULES
 *   - PUBLIC data only: kid, SHA-256 fingerprint of the SPKI DER, PEM-encoded SPKI public key.
 *     Private halves are never stored in a repository.
 *   - Normally this file is generated, never edited by hand.
 *     Until it is filled in, each entry holds a stand-in value; the build refuses to ship while any
 *     remains (scripts/check-keyring-placeholders.mjs).
 */

export interface CeremonyPublicEntry {
  kid: string;
  /** SHA-256 (lower-case hex) of the SPKI DER bytes of the public key. */
  fingerprint: string;
  /** PEM-encoded SPKI public key. */
  publicKey: string;
}

export const CEREMONY_OUTPUT: { ra: CeremonyPublicEntry; cf: CeremonyPublicEntry; bundle: CeremonyPublicEntry } = {
  ra: {
    kid: "ra-k2-2026",
    fingerprint: "a3c0751a14d6933c2e0dbfca69f50a0189ed749153d62b1b76727fc714bf043c",
    publicKey: "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAI5sKq3SF+toDqPO3Brz1FkWOl7INL/O9K3BBtPS3zTo=\n-----END PUBLIC KEY-----",
  },
  cf: {
    kid: "cf-k2-2026",
    fingerprint: "3535a1f5bdd798af75e893aaa93346df6b7e421632ca8bc0105ff866a89c0cee",
    publicKey: "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAjyVy38g4NcfXqD3WmZP7ygit8m4aoywK0KsA0jYiEv4=\n-----END PUBLIC KEY-----",
  },
  bundle: {
    kid: "k3-2026",
    fingerprint: "3cbd12f5c1ef05c33527899f0d074585cb26bacdfe6f13a63cbea243d5c8e57e",
    publicKey: "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA4seZCqwlRq+QzOsIA6+RJUHXHWe4lb1ok6hwL0Bvqzs=\n-----END PUBLIC KEY-----",
  },
};
