package io.github.garyttierney.chacha20poly1305;

import io.github.garyttierney.chacha20poly1305.common.SecretKey;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class AeadCipherTest {

	@Before
	public void setUp() throws Exception {
		System.loadLibrary("chacha20poly1305jni");
	}

	@Test
	public void integration() throws Exception {
		SecureRandom rng = new SecureRandom();

		byte[] key = new byte[AeadMode.CHACHA20_POLY1305.getKeySize()];
		rng.nextBytes(key);

		AeadCipher cipher = new AeadCipher(new SecretKey(key), AeadMode.CHACHA20_POLY1305);

		ByteBuffer msg = wrapDirect("ABCD".getBytes());
		ByteBuffer additional = wrapDirect("EFGH".getBytes());
		ByteBuffer nonce = cipher.randomNonce();

		ByteBuffer ciphertext = cipher.encrypt(msg, 4, additional, 4, nonce);
		ByteBuffer plaintext = cipher.decrypt(ciphertext, ciphertext.capacity(), additional, 4, nonce);

		byte[] data = new byte[4];
		plaintext.get(data);

		Assert.assertArrayEquals("ABCD".getBytes(), data);
	}

	private static ByteBuffer wrapDirect(byte[] data) {
		ByteBuffer buffer = ByteBuffer.allocateDirect(data.length);
		buffer.put(data);
		buffer.position(0);

		return buffer;
	}
}