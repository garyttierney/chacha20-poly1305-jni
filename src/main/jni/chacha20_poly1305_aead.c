#include "chacha20_poly1305_aead.h"

#include <sodium/crypto_aead_chacha20poly1305.h>
#include <sodium/crypto_aead_xchacha20poly1305.h>

#include <assert.h>
#include <stdint.h>

/**
 * A table of secret key sizes in bytes to be used for each
 * ChaCha20-Poly1305 mode.
 */
static unsigned int KEY_SIZES[CHACHA20_POLY1305_MODES] = {
	    [CHACHA20_POLY1305] = crypto_aead_chacha20poly1305_KEYBYTES,
	    [CHACHA20_POLY1305_IETF] = crypto_aead_chacha20poly1305_ietf_KEYBYTES,
	    [XCHACHA20_POLY1305] = crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
};

/**
 * A table of public nonce sizes in bytes to be used for each
 * ChaCha20-Poly1305 mode.
 */
static unsigned int NONCE_SIZES[CHACHA20_POLY1305_MODES] = {
	    [CHACHA20_POLY1305] = crypto_aead_chacha20poly1305_NPUBBYTES,
	    [CHACHA20_POLY1305_IETF] = crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
	    [XCHACHA20_POLY1305] = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
};

/**
 * A table of HMAC sizes in bytes to be used for each
 * ChaCha20-Poly1305 mode.
 */
static unsigned int AUTH_SIZES[CHACHA20_POLY1305_MODES] = {
	    [CHACHA20_POLY1305] = crypto_aead_chacha20poly1305_ABYTES,
	    [CHACHA20_POLY1305_IETF] = crypto_aead_chacha20poly1305_ietf_ABYTES,
	    [XCHACHA20_POLY1305] = crypto_aead_xchacha20poly1305_ietf_ABYTES,
};

/**
 * Ensures that a direct buffer object has a capacity of at least
 * @expected_length
 * bytes.
 *
 * @buf The buffer object to check the capacity of.
 * @expected_length The minimum capacity for buffer objects.
 */
int ensure_capacity(JNIEnv *env, jobject buf, uint64_t expected_length)
{
	jlong capacity = (*env)->GetDirectBufferCapacity(env, buf);
	return capacity >= expected_length;
}

/**
 * Helper function to get the address of a direct mapped buffer.
 *
 * @env The JVM environment.
 * @obj The Java ByteBuffer object.
 */
unsigned char *get_buffer_addr(JNIEnv *env, jobject obj)
{
	return (*env)->GetDirectBufferAddress(env, obj);
}

int jni_chacha20_poly1305_aead_decrypt(enum chacha20_poly1305_mode mode,
				       JNIEnv *env, jobject key,
				       jobject ciphertext, jint ciphertext_len,
				       jobject ad, jint ad_len, jobject nonce,
				       jobject output)
{
	if (mode < 0 || mode >= CHACHA20_POLY1305_MODES) {
		return 0;
	}

	unsigned char *key_buf = get_buffer_addr(env, key);
	unsigned char *ciphertext_buf = get_buffer_addr(env, ciphertext);
	unsigned char *ad_buf = get_buffer_addr(env, ad);
	unsigned char *nonce_buf = get_buffer_addr(env, nonce);
	unsigned char *output_buf = get_buffer_addr(env, output);
	unsigned long long output_len;
	int has_capacity;

	if (!key || !ciphertext || !ad || !nonce || !output) {
		return 0;
	}

	uint64_t expected_len = ciphertext_len - AUTH_SIZES[mode];

	has_capacity = ensure_capacity(env, key, KEY_SIZES[mode]);
	has_capacity &= ensure_capacity(env, nonce, NONCE_SIZES[mode]);
	has_capacity &= ensure_capacity(env, output, expected_len);

	if (!has_capacity) {
		return -1;
	}

	int valid = -1;

	switch (mode) {
	case CHACHA20_POLY1305:
		valid = crypto_aead_chacha20poly1305_decrypt(
		    output_buf, &output_len, NULL, ciphertext_buf,
		    ciphertext_len, ad_buf, ad_len, nonce_buf, key_buf);
		break;
	case CHACHA20_POLY1305_IETF:
		valid = crypto_aead_chacha20poly1305_ietf_decrypt(
		    output_buf, &output_len, NULL, ciphertext_buf,
		    ciphertext_len, ad_buf, ad_len, nonce_buf, key_buf);
		break;
	case XCHACHA20_POLY1305:
		valid = crypto_aead_xchacha20poly1305_ietf_decrypt(
		    output_buf, &output_len, NULL, ciphertext_buf,
		    ciphertext_len, ad_buf, ad_len, nonce_buf, key_buf);
		break;
	}

	return valid == 0;
}

int jni_chacha20_poly1305_aead_encrypt(enum chacha20_poly1305_mode mode,
				       JNIEnv *env, jobject key,
				       jobject plaintext, jint plaintext_len,
				       jobject ad, jint ad_len, jobject nonce,
				       jobject output)
{
	if (mode < 0 || mode >= CHACHA20_POLY1305_MODES) {
		return 0;
	}

	unsigned char *key_buf = get_buffer_addr(env, key);
	unsigned char *plaintext_buf = get_buffer_addr(env, plaintext);
	unsigned char *ad_buf = get_buffer_addr(env, ad);
	unsigned char *nonce_buf = get_buffer_addr(env, nonce);
	unsigned char *output_buf = get_buffer_addr(env, output);
	unsigned long long output_len;
	int has_capacity;

	if (!key || !plaintext || !ad || !nonce || !output) {
		return 0;
	}

	uint64_t expected_len = plaintext_len + AUTH_SIZES[mode];

	has_capacity = ensure_capacity(env, key, KEY_SIZES[mode]);
	has_capacity &= ensure_capacity(env, nonce, NONCE_SIZES[mode]);
	has_capacity &= ensure_capacity(env, output, expected_len);

	if (!has_capacity) {
		return -1;
	}

	switch (mode) {
	case CHACHA20_POLY1305:
		crypto_aead_chacha20poly1305_encrypt(
		    output_buf, &output_len, plaintext_buf, plaintext_len,
		    ad_buf, ad_len, NULL, nonce_buf, key_buf);
		break;
	case CHACHA20_POLY1305_IETF:
		crypto_aead_chacha20poly1305_ietf_encrypt(
		    output_buf, &output_len, plaintext_buf, plaintext_len,
		    ad_buf, ad_len, NULL, nonce_buf, key_buf);
		break;
	case XCHACHA20_POLY1305:
		crypto_aead_xchacha20poly1305_ietf_encrypt(
		    output_buf, &output_len, plaintext_buf, plaintext_len,
		    ad_buf, ad_len, NULL, nonce_buf, key_buf);
		break;
	}

	/* If this assertion fails we've just trashed the JVMs
	 * heap, oops */
	assert(output_len <= expected_len);
	return 1;
}
