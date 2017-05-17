package io.github.garyttierney.chacha20poly1305;

import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertThat;

import io.github.garyttierney.chacha20poly1305.common.SecretKey;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collection;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

@RunWith(Parameterized.class)
public class AeadCipherIntegrationTest {

	private final AeadMode cipherMode;

	@BeforeClass
	public static void setUp() throws Exception {
		System.loadLibrary("chacha20poly1305jni");
	}

	@Parameters(name = "aead-integration-test-{index}: {0}")
	public static Collection<Object[]> data() {
		return Arrays.asList(
				new Object[]{AeadMode.CHACHA20_POLY1305},
				new Object[]{AeadMode.CHACHA20_POLY1305_IETF},
				new Object[]{AeadMode.XCHACHA20_POLY1305}
		);
	}

	public AeadCipherIntegrationTest(AeadMode cipherMode) {
		this.cipherMode = cipherMode;
	}

	/**
	 * Test that a message encrypted by a cipher can be successfully encrypted/signed and decrypted/authenticated.
	 */
	@Test
	public void integration() throws Exception {
		SecureRandom rng = new SecureRandom();

		byte[] key = new byte[cipherMode.getKeySize()];
		rng.nextBytes(key);

		AeadCipher cipher = new AeadCipher(new SecretKey(key), cipherMode);

		byte[] plaintextBytes = "ABCD".getBytes();
		byte[] additionalBytes = "EFGH".getBytes();

		ByteBuffer msg = wrapDirect(plaintextBytes);
		ByteBuffer additional = wrapDirect(additionalBytes);
		ByteBuffer nonce = cipher.randomNonce();

		ByteBuffer ciphertext = cipher.encrypt(msg, plaintextBytes.length, additional,
											   additionalBytes.length, nonce);

		ByteBuffer plaintext = cipher.decrypt(ciphertext, ciphertext.capacity(),
											  additional, additionalBytes.length, nonce);

		byte[] plaintextData = new byte[4];
		plaintext.get(plaintextData);

		assertThat(plaintextData, equalTo(plaintextBytes));
	}

	private static ByteBuffer wrapDirect(byte[] data) {
		ByteBuffer buffer = ByteBuffer.allocateDirect(data.length);
		buffer.put(data);
		buffer.position(0);

		return buffer;
	}
}