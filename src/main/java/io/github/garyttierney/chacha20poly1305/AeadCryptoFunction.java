package io.github.garyttierney.chacha20poly1305;

import java.nio.ByteBuffer;

@FunctionalInterface
interface AeadCryptoFunction {
	int apply(ByteBuffer keyBuffer, ByteBuffer input,
			  int inputLength, ByteBuffer additionalData,
			  int additionalDataLength, ByteBuffer nonce,
			  ByteBuffer target);
}
