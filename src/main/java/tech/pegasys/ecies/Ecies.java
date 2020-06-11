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

import java.security.SecureRandom;
import org.apache.tuweni.bytes.Bytes;
import tech.pegasys.teku.bls.BLSKeyPair;
import tech.pegasys.teku.bls.BLSPublicKey;
import tech.pegasys.teku.bls.BLSSecretKey;
import tech.pegasys.teku.bls.mikuli.G1Point;

public class Ecies {

  /**
   * Encrypt a message with ECIES.
   *
   * @param theirPublicKey The BLS public key of the recipient
   * @param message The message to be encrypted
   * @return An EncryptedMessage object containing my public key, a nonce, and the cipher text
   */
  public static EncryptedMessage encrypt(BLSPublicKey theirPublicKey, Bytes message) {

    // Generate ephemeral key pair
    final SecureRandom srng = new SecureRandom();
    final BLSKeyPair myKeys = BLSKeyPair.random(srng);

    // Do key agreement to create the shared secret
    final G1Point sharedSecretPoint =
        theirPublicKey.getPublicKey().g1Point().mul(myKeys.getSecretKey().getScalarValue());

    // Overwrite in-place the ephemeral secret key so that it is no longer in memory
    myKeys.getSecretKey().destroy();

    // Hash the point into a symmetric key
    final Bytes sharedSecret = Util.deriveKey(sharedSecretPoint);

    // Since the message key is random, we don't necessarily need a unique nonce, but we'll set it
    // randomly in any case
    final Bytes nonce = Bytes.random(12, srng);

    // Encrypt message using the shared secret as the key
    final Bytes cipherText = Util.aesgcmEncrypt(sharedSecret, nonce, message);

    return new EncryptedMessage(myKeys.getPublicKey(), nonce, cipherText);
  }

  /**
   * Decrypt a message with ECIES
   *
   * @param mySecretKey The BLS secret key of the recipient
   * @param encryptedMessage An EncryptedMessage object containing my public key, a nonce, and the
   *     cipher text
   * @return The decrypted message as Bytes
   */
  public static Bytes decrypt(BLSSecretKey mySecretKey, EncryptedMessage encryptedMessage) {

    // Do key agreement to create the shared secret
    final G1Point sharedSecretPoint =
        encryptedMessage.getPublicKey().getPoint().mul(mySecretKey.getScalarValue());

    // Hash the point into a symmetric key
    final Bytes sharedSecret = Util.deriveKey(sharedSecretPoint);

    // Decrypt message using the shared secret as the key
    return Util.aesgcmDecrypt(
        sharedSecret, encryptedMessage.getNonce(), encryptedMessage.getCipherText());
  }
}
