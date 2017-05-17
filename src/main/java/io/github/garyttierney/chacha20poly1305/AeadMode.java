package io.github.garyttierney.chacha20poly1305;

/**
 * Mode of operation (one of the ChaCha20-Poly1305 AEAD implementations) for the {@link AeadCipher}.
 */
public enum AeadMode {
	CHACHA20_POLY1305(ChaCha20Poly1305.KEYBYTES, ChaCha20Poly1305.NPUBBYTES, ChaCha20Poly1305.ABYTES),
	CHACHA20_POLY1305_IETF(ChaCha20Poly1305Ietf.KEYBYTES, ChaCha20Poly1305Ietf.NPUBBYTES, ChaCha20Poly1305Ietf.ABYTES),
	XCHACHA20_POLY1305(XChaCha20Poly1305.KEYBYTES, XChaCha20Poly1305.NPUBBYTES, XChaCha20Poly1305.ABYTES);

	/**
	 * The number of bytes in a secret key for this cipher mode.
	 */
	private final int keySize;

	/**
	 * The number of bytes in a public nonce for this cipher mode.
	 */
	private final int nonceSize;

	/**
	 * The number of bytes in a HMAC for this cipher mode.
	 */
	private final int hmacSize;

	AeadMode(int keySize, int nonceSize, int hmacSize) {
		this.keySize = keySize;
		this.nonceSize = nonceSize;
		this.hmacSize = hmacSize;
	}

	public int getKeySize() {
		return keySize;
	}

	public int getNonceSize() {
		return nonceSize;
	}

	public int getHmacSize() {
		return hmacSize;
	}

}
