# chacha20-poly1305-jni

chacha20-poly1305-jni is a small wrapper around libsodium's ChaCha20-Poly1305 AEAD
primitives.


## Example code

```java
class ChaCha20Poly1305JniExample {
    public static void main(String[] argv) {
    	SecureRandom random = new SecureRandom();
    	
    	AeadMode mode = AeadMode.CHACHA20_POLY1305;
    	byte[] key = new byte[mode.getKeySize()];
    	
    	byte[] plaintextData = "ABC".getBytes();
    	byte[] additionalData = "DEF".getBytes();
    	
    	AeadCipher cipher = new AeadCipher(new SecretKey(key), mode);
    	ByteBuffer ciphertext = cipher.encrypt(msg, plaintextBytes.length, additional,
                                             additionalBytes.length, nonce);
    }
    
    private static ByteBuffer wrapDirect(byte[] data) {
    	  ByteBuffer buffer = ByteBuffer.allocateDirect(data.length);
    	  buffer.put(data);
    	  buffer.position(0);
    	  
    	  return buffer;
    }
}
```

## Thread-safety

After `System.loadLibrary("chacha20poly1305jni")` is called the native library will
initialize libsodium and all further calls to `AeadCipher` crypto functions will be
thread-safe.
