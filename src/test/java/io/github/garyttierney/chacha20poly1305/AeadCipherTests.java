package io.github.garyttierney.chacha20poly1305;

import io.github.garyttierney.chacha20poly1305.common.SecretKey;
import java.nio.ByteBuffer;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class AeadCipherTests {

	@Rule
	public final ExpectedException exception = ExpectedException.none();

	/**
	 * Verify that an exception is thrown when an {@link AeadCipher} is initialized with a bad key.
	 */
	@Test
	public void exceptionOnBadKeySize() throws Exception {
		AeadMode mode = AeadMode.CHACHA20_POLY1305;
		SecretKey key = new SecretKey(new byte[mode.getKeySize() - 1]);

		exception.expect(AeadCipherException.class);
		new AeadCipher(key, mode);
	}

	/**
	 * Verify that an exception is thrown when unmapped buffers are passsed to {@link AeadCipher#encrypt(ByteBuffer,
	 * int, ByteBuffer, int, ByteBuffer)}.
	 */
	@Test
	public void exceptionOnEncryptingUmappedBuffer() throws Exception {
		AeadMode mode = AeadMode.CHACHA20_POLY1305;

		ByteBuffer buffer = ByteBuffer.wrap("ABC".getBytes());
		ByteBuffer additional = ByteBuffer.wrap("DEF".getBytes());
		ByteBuffer nonce = ByteBuffer.allocate(mode.getNonceSize());

		byte[] keyData = new byte[mode.getKeySize()];
		AeadCipher cipher = new AeadCipher(new SecretKey(keyData), mode);

		exception.expect(AeadCipherException.class);
		exception.expectMessage(
			"This cipher can only be used with direct mapped buffers.  See ByteBuffer.allocateDirect(int)");
		cipher.encrypt(buffer, 3, additional, 3, nonce);
	}

	/**
	 * Verify that an exception is thrown when unmapped buffers are passsed to {@link AeadCipher#decrypt(ByteBuffer,
	 * int, ByteBuffer, int, ByteBuffer)}.
	 */
	@Test
	public void exceptionOnDecryptingUmappedBuffer() throws Exception {
		AeadMode mode = AeadMode.CHACHA20_POLY1305;

		ByteBuffer buffer = ByteBuffer.wrap("ABC".getBytes());
		ByteBuffer additional = ByteBuffer.wrap("DEF".getBytes());
		ByteBuffer nonce = ByteBuffer.allocate(mode.getNonceSize());

		byte[] keyData = new byte[mode.getKeySize()];
		AeadCipher cipher = new AeadCipher(new SecretKey(keyData), mode);

		exception.expect(AeadCipherException.class);
		exception.expectMessage(
			"This cipher can only be used with direct mapped buffers.  See ByteBuffer.allocateDirect(int)");
		cipher.decrypt(buffer, 3, additional, 3, nonce);
	}
}
