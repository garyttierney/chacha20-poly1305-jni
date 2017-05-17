package io.github.garyttierney.chacha20poly1305.common;

import java.nio.ByteBuffer;

/**
 * A representation of a {@code secret} symmetric cipher key.
 *
 * @author gtierney
 */
public final class SecretKey {

	/**
	 * A direct buffer containing the secret key.
	 */
	private final ByteBuffer key;

	/**
	 * The length of the secret key in bytes.
	 */
	private final int keySize;

	/**
	 * Create a new {@code SecretKey} with the given {@code key} and allocate
	 * a new direct buffer.
	 *
	 * @param key The key representation of this key.
	 */
	public SecretKey(byte[] key) {
		this.key = ByteBuffer.allocateDirect(key.length);
		this.key.put(key);
		this.key.position(0);
		this.keySize = key.length;
	}

	public ByteBuffer getKey() {
		return key;
	}

	public int getKeySize() {
		return keySize;
	}
}
