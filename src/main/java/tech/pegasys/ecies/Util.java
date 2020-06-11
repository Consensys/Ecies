/*
 * Copyright 2020 ConsenSys AG.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package tech.pegasys.ecies;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.tuweni.bytes.Bytes;
import tech.pegasys.teku.bls.mikuli.G1Point;

public class Util {

  // Acceptable values are 16, 24, or 32. Any of these is fine.
  private static final int KEY_LENGTH_BYTES = 32;

  /**
   * Create a symmetric key by hashing a G1Point.
   *
   * <p>The key is KEY_LENGTH_BYTES bytes long.
   *
   * @param p The G1 point to hash
   * @return A KEY_LENGTH_BYTES long key as Bytes
   */
  static Bytes deriveKey(G1Point p) {
    try {
      MessageDigest md = MessageDigest.getInstance("SHA-256");
      md.update(p.toBytes().toArray());
      return Bytes.wrap(md.digest()).slice(0, KEY_LENGTH_BYTES);
    } catch (NoSuchAlgorithmException | RuntimeException e) {
      throw new RuntimeException("Failed to create shared secret key", e);
    }
  }

  /**
   * Encrypt with AES/GCM.
   *
   * <p>Note that this does not implement the optional additional authenticated data (AAD).
   *
   * @param key KEY_LENGTH_BYTES byte symmetric key
   * @param nonce 12 byte nonce/IV
   * @param message Arbitrary length message to encrypt
   * @return The encrypted message
   */
  static Bytes aesgcmEncrypt(Bytes key, Bytes nonce, Bytes message) {
    try {
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      cipher.init(
          Cipher.ENCRYPT_MODE,
          new SecretKeySpec(key.toArray(), "AES"),
          new GCMParameterSpec(128, nonce.toArray()));
      return Bytes.wrap(cipher.doFinal(message.toArray()));
    } catch (NoSuchAlgorithmException
        | NoSuchPaddingException
        | InvalidAlgorithmParameterException
        | InvalidKeyException e) {
      throw new IllegalStateException("Encryption algorithm is incorrectly configured", e);
    } catch (BadPaddingException | IllegalBlockSizeException | RuntimeException e) {
      throw new RuntimeException("Failed to encrypt message", e);
    }
  }

  /**
   * Decrypt with AES/GCM
   *
   * <p>Note that this does not implement the optional additional authenticated data (AAD).
   *
   * @param key KEY_LENGTH_BYTES byte symmetric key
   * @param nonce 12 byte nonce/IV
   * @param ciphertext The encrypted message to decrypt
   * @return The decrypted message
   */
  static Bytes aesgcmDecrypt(Bytes key, Bytes nonce, Bytes ciphertext) {
    try {
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      cipher.init(
          Cipher.DECRYPT_MODE,
          new SecretKeySpec(key.toArray(), "AES"),
          new GCMParameterSpec(128, nonce.toArray()));
      return Bytes.wrap(cipher.doFinal(ciphertext.toArray()));
    } catch (NoSuchAlgorithmException
        | NoSuchPaddingException
        | InvalidAlgorithmParameterException
        | InvalidKeyException e) {
      throw new IllegalStateException("Decryption algorithm is incorrectly configured", e);
    } catch (BadPaddingException | IllegalBlockSizeException | RuntimeException e) {
      throw new RuntimeException("Failed to decrypt message", e);
    }
  }
}
