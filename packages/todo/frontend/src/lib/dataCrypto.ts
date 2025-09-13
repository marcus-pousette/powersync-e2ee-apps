import sodium from "libsodium-wrappers-sumo";
import type { CipherEnvelope } from "@crypto/interface";
import { bytesToBase64, base64ToBytes } from "@crypto/interface";

const ALG = "xchacha20poly1305/raw";

export class DataCrypto {
  constructor(private key: Uint8Array) {}

  async encrypt(plain: Uint8Array, aad?: string): Promise<CipherEnvelope> {
    await sodium.ready;
    const nonce = sodium.randombytes_buf(
      sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
    );
    const ct = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
      plain,
      aad ? new TextEncoder().encode(aad) : null,
      null,
      nonce,
      this.key,
    );
    return {
      header: {
        v: 1,
        alg: ALG,
        aad,
        kdf: { saltB64: "" },
      },
      nB64: bytesToBase64(nonce),
      cB64: bytesToBase64(ct),
    };
  }

  async decrypt(env: CipherEnvelope, aad?: string): Promise<Uint8Array> {
    await sodium.ready;
    const nonce = base64ToBytes(env.nB64);
    const ct = base64ToBytes(env.cB64);
    return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null,
      ct,
      (aad ?? env.header.aad)
        ? new TextEncoder().encode(aad ?? env.header.aad!)
        : null,
      nonce,
      this.key,
    );
  }
}

export async function generateDEK(): Promise<Uint8Array> {
  await sodium.ready;
  return sodium.randombytes_buf(32);
}
