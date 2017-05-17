#include "chacha20_poly1305_aead.h"

#include <jni.h>
#include <sodium.h>

JNIEXPORT jint JNICALL chacha20_poly1305_decrypt_method(
    JNIEnv *env, jclass cls, jobject key, jobject plaintext, jint plaintext_len,
    jobject ad, jint ad_len, jobject nonce, jobject output)
{
	return jni_chacha20_poly1305_aead_decrypt(CHACHA20_POLY1305, env, key,
						  plaintext, plaintext_len, ad,
						  ad_len, nonce, output);
}

JNIEXPORT jint JNICALL chacha20_poly1305_encrypt_method(
    JNIEnv *env, jclass cls, jobject key, jobject plaintext, jint plaintext_len,
    jobject ad, jint ad_len, jobject nonce, jobject output)
{
	return jni_chacha20_poly1305_aead_encrypt(CHACHA20_POLY1305, env, key,
						  plaintext, plaintext_len, ad,
						  ad_len, nonce, output);
}

JNIEXPORT jint JNICALL chacha20_poly1305_ietf_decrypt_method(
    JNIEnv *env, jclass cls, jobject key, jobject plaintext, jint plaintext_len,
    jobject ad, jint ad_len, jobject nonce, jobject output)
{
	return jni_chacha20_poly1305_aead_decrypt(CHACHA20_POLY1305_IETF, env,
						  key, plaintext, plaintext_len,
						  ad, ad_len, nonce, output);
}

JNIEXPORT jint JNICALL chacha20_poly1305_ietf_encrypt_method(
    JNIEnv *env, jclass cls, jobject key, jobject plaintext, jint plaintext_len,
    jobject ad, jint ad_len, jobject nonce, jobject output)
{
	return jni_chacha20_poly1305_aead_encrypt(CHACHA20_POLY1305_IETF, env,
						  key, plaintext, plaintext_len,
						  ad, ad_len, nonce, output);
}

JNIEXPORT jint JNICALL xchacha20_poly1305_decrypt_method(
    JNIEnv *env, jclass cls, jobject key, jobject plaintext, jint plaintext_len,
    jobject ad, jint ad_len, jobject nonce, jobject output)
{
	return jni_chacha20_poly1305_aead_decrypt(XCHACHA20_POLY1305, env, key,
						  plaintext, plaintext_len, ad,
						  ad_len, nonce, output);
}

JNIEXPORT jint JNICALL xchacha20_poly1305_encrypt_method(
    JNIEnv *env, jclass cls, jobject key, jobject plaintext, jint plaintext_len,
    jobject ad, jint ad_len, jobject nonce, jobject output)
{
	return jni_chacha20_poly1305_aead_encrypt(XCHACHA20_POLY1305, env, key,
						  plaintext, plaintext_len, ad,
						  ad_len, nonce, output);
}

struct jni_crypto_methods {
	const char *class;
	void *encrypt;
	void *decrypt;
};

#define CRYPTO_METHOD_SIGNATURE "(Ljava/nio/ByteBuffer;Ljava/nio/ByteBuffer;ILjava/nio/ByteBuffer;ILjava/nio/ByteBuffer;Ljava/nio/ByteBuffer;)I"
#define CHACHA20_POLY1305_CLASS "io/github/garyttierney/chacha20poly1305/ChaCha20Poly1305"
#define CHACHA20_POLY1305_IETF_CLASS "io/github/garyttierney/chacha20poly1305/ChaCha20Poly1305Ietf"
#define XCHACHA20_POLY1305_CLASS "io/github/garyttierney/chacha20poly1305/XChaCha20Poly1305"

static struct jni_crypto_methods JNI_METHODS[CHACHA20_POLY1305_MODES] = {
	{ CHACHA20_POLY1305_CLASS, chacha20_poly1305_encrypt_method,
	  chacha20_poly1305_decrypt_method },
	{ CHACHA20_POLY1305_IETF_CLASS, chacha20_poly1305_ietf_encrypt_method,
	  chacha20_poly1305_ietf_decrypt_method },
	{ XCHACHA20_POLY1305_CLASS, xchacha20_poly1305_encrypt_method,
	  xchacha20_poly1305_decrypt_method },
};

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved)
{
	jint rc = 1;

	union {
		JNIEnv *env;
		void *venv;
	} uenv;

	if ((*vm)->GetEnv(vm, &uenv.venv, JNI_VERSION_1_4) != JNI_OK) {
		return rc;
	}

	if (sodium_init() == -1) {
		return rc;
	}

	JNIEnv *env = uenv.env;
	int num_method_specs = sizeof(JNI_METHODS) / sizeof(JNI_METHODS[0]);

	for (int i = 0; i < num_method_specs; i++) {
		struct jni_crypto_methods method_spec = JNI_METHODS[i];
		jclass cls = (*env)->FindClass(env, method_spec.class);

		if (cls == NULL) {
			continue;
		}

		JNINativeMethod methods[2] = {
			{ "decrypt", CRYPTO_METHOD_SIGNATURE,
			  method_spec.decrypt },
			{ "encrypt", CRYPTO_METHOD_SIGNATURE,
			  method_spec.encrypt }
		};

		if ((*env)->RegisterNatives(env, cls, methods, 2) < 0) {
			// log error
		}
	}

	rc = JNI_VERSION_1_4;
	return rc;
}
