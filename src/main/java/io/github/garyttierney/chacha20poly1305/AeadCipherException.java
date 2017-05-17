package io.github.garyttierney.chacha20poly1305;

/**
 * An exception thrown when the libsodium AEAD primitives return a fatal error or when an error prevents
 * a cipher from being created.
 */
public final class AeadCipherException extends Exception {

	public AeadCipherException(String message) {
		super(message);
	}
}
