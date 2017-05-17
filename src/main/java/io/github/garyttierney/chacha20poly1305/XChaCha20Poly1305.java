package io.github.garyttierney.chacha20poly1305;

import java.nio.ByteBuffer;

final class XChaCha20Poly1305 {

	public static final int KEYBYTES = 32;
	public static final int NPUBBYTES = 24;
	public static final int ABYTES = 16;

	static native int decrypt(ByteBuffer keyBuffer, ByteBuffer ciphertext,
							  int ciphertextLength, ByteBuffer additionalData,
							  int additionalDataLength, ByteBuffer nonce,
							  ByteBuffer target);

	static native int encrypt(ByteBuffer keyBuffer, ByteBuffer plaintext,
							  int plaintextLength, ByteBuffer additionalData,
							  int additionalDataLength, ByteBuffer nonce,
							  ByteBuffer target);
}
