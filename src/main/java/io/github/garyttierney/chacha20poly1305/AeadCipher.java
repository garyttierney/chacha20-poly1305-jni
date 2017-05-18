package io.github.garyttierney.chacha20poly1305;

import io.github.garyttierney.chacha20poly1305.common.SecretKey;
import java.nio.ByteBuffer;
import java.security.SecureRandom;

/**
 * An AEAD cipher implementation which implements encryption/decryption of authenticated messaages
 * with additional data using variants of ChaCha20-Poly1305.  Calls to {@code AeadCipher} crypto functions
 * are thread-safe.
 */
public final class AeadCipher {

	/**
	 * Secure random number generator to generate appropriately sized nonce values.
	 */
	private static final SecureRandom NONCE_GENERATOR = new SecureRandom();

	/**
	 * The secret key used to encrypt and authenticate messages.
	 */
	private final SecretKey key;

	/**
	 * The cipher mode to use.
	 */
	private final AeadMode mode;

	/**
	 * Create a new {@code AeadCipher} with the given secret {@code key} and {@code mode} of operation.
	 *
	 * @param key The secret key used for encryption / decryption.
	 * @param mode The ChaCha20-Poly1305 implementation mode to use.
	 * @throws AeadCipherException If the {@link SecretKey} given cannot be used with the provided {@link AeadMode}.
	 */
	public AeadCipher(SecretKey key, AeadMode mode) throws AeadCipherException {
		if (key.getKeySize() != mode.getKeySize()) {
			throw new AeadCipherException("Invalid key length");
		}

		this.key = key;
		this.mode = mode;
	}

	/**
	 * Generate a random nonce suitable for use with this cipher.
	 *
	 * @return A direct mapped buffer containing a random nonce value.
	 */
	public ByteBuffer randomNonce() {
		int nonceLength = mode.getNonceSize();
		byte[] nonce = new byte[nonceLength];

		NONCE_GENERATOR.nextBytes(nonce);

		ByteBuffer nonceBuffer = ByteBuffer.allocateDirect(nonceLength);
		nonceBuffer.put(nonce);
		nonceBuffer.position(0);
		return nonceBuffer;
	}

	/**
	 * Decrypt and verify a {@code ciphertext} of {@code ciphertextLength} bytes using the stored {@link SecretKey} and
	 * {@code nonce}.
	 *
	 * @param ciphertext The encrypted ciphertext to decrypt.
	 * @param ciphertextLength The length of the ciphertext in the buffer.
	 * @param additionalData A buffer containing authenticated data associated with the message.
	 * @param additionalDataLength The length of the authenticated data in the buffer.
	 * @param nonce The nonce used to encrypt this message.
	 * @return A plaintext matching the length of {@code ciphertextLength}.
	 * @throws AeadVerificationException If the message failed authentication.
	 * @throws AeadCipherException If a fatal error occurred during decryption.
	 */
	public ByteBuffer decrypt(ByteBuffer ciphertext, int ciphertextLength,
							  ByteBuffer additionalData, int additionalDataLength,
							  ByteBuffer nonce) throws AeadCipherException, AeadVerificationException {

		if (!ciphertext.isDirect() || !additionalData.isDirect() || !nonce.isDirect()) {
			throw new AeadCipherException(
				"This cipher can only be used with direct mapped buffers.  See ByteBuffer.allocateDirect(int)");
		}

		int outputLength = ciphertextLength - mode.getHmacSize();
		ByteBuffer output = ByteBuffer.allocateDirect(outputLength);

		AeadCryptoFunction decryptFunction = mode.getDecryptFunction();
		int rc = decryptFunction.apply(key.getKey(), ciphertext, ciphertextLength,
									   additionalData, additionalDataLength, nonce, output);

		if (rc == 0) {
			throw new AeadVerificationException();
		} else if (rc < 0) {
			throw new AeadCipherException("Fatal error occurred during decryption");
		}

		return output;
	}

	/**
	 * Encrypt and sign a {@code plaintext} of {@code plaintextLength} bytes using the stored {@link SecretKey} and
	 * {@code nonce}.
	 *
	 * @param plaintext The encrypted plaintext to decrypt.
	 * @param plaintextLength The length of the plaintext in the buffer.
	 * @param additionalData A buffer containing authenticated data associated with the message.
	 * @param additionalDataLength The length of the authenticated data in the buffer.
	 * @param nonce The nonce used to encrypt this message.
	 * @return A ciphertext matching the length of {@code plaintextLength} plus the length of the HMAC.
	 * @throws AeadCipherException If a fatal error occurred during encryption.
	 */
	public ByteBuffer encrypt(ByteBuffer plaintext, int plaintextLength,
							  ByteBuffer additionalData, int additionalDataLength,
							  ByteBuffer nonce) throws AeadCipherException {

		if (!plaintext.isDirect() || !additionalData.isDirect() || !nonce.isDirect()) {
			throw new AeadCipherException(
				"This cipher can only be used with direct mapped buffers.  See ByteBuffer.allocateDirect(int)");
		}

		int outputLength = plaintextLength + mode.getHmacSize();
		ByteBuffer output = ByteBuffer.allocateDirect(outputLength);

		AeadCryptoFunction encryptFunction = mode.getEncryptFunction();
		int rc = encryptFunction.apply(key.getKey(), plaintext, plaintextLength,
									   additionalData, additionalDataLength, nonce, output);

		if (rc != 1) {
			throw new AeadCipherException("Fatal error occurred during encryption");
		}

		return output;
	}
}
