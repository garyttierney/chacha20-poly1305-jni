package io.github.garyttierney.chacha20poly1305;

import java.nio.ByteBuffer;

/**
 * An exception thrown when an encrypted message fails authentication.
 *
 * @see AeadCipher#decrypt(ByteBuffer, int, ByteBuffer, int, ByteBuffer)
 */
public class AeadVerificationException extends Exception {

	public AeadVerificationException() {
		super();
	}
}
