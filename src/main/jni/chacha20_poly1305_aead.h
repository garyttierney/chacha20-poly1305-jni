#ifndef JNI_CHACHA20POLY1305_AEAD_H
#define JNI_CHACHA20POLY1305_AEAD_H

#include <jni.h>

/**
 * The mode which defines the parameters of the ChaCha20-Poly1305 AEAD operator.
 */
enum chacha20_poly1305_mode {
	CHACHA20_POLY1305 = 0,
	CHACHA20_POLY1305_IETF = 1,
	XCHACHA20_POLY1305 = 2
};

#define CHACHA20_POLY1305_MODES 3

/**
 * Native interface to using libsodiums ChaCha20-Poly1305-IETF AEAD mode for
 * decryption.
 *
 * @key A direct buffer object to the key data.
 * @ciphertext A direct buffer object to the ciphertext to decrypt.
 * @ciphertext_len The length of the ciphertext in bytes.
 * @ad A direct buffer object to additional authentication data.
 * @ad_len The length of the additional authentication data in bytes.
 * @nonce The public nonce used to pad the ciphertext.
 * @output A direct buffer object to store the decryption result in.
 *
 * @return 1 on success, 0 on failure, < 0 on error.
 */
int jni_chacha20_poly1305_aead_decrypt(enum chacha20_poly1305_mode mode,
				       JNIEnv *env, jobject key,
				       jobject ciphertext, jint ciphertext_len,
				       jobject ad, jint ad_len, jobject nonce,
				       jobject output);

int jni_chacha20_poly1305_aead_encrypt(enum chacha20_poly1305_mode mode,
				       JNIEnv *env, jobject key,
				       jobject plaintext, jint plaintext_len,
				       jobject ad, jint ad_len, jobject nonce,
				       jobject output);

#endif
