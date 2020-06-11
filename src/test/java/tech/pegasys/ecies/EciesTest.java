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

import static java.nio.charset.StandardCharsets.UTF_16;
import static org.junit.jupiter.api.Assertions.assertEquals;

import org.apache.tuweni.bytes.Bytes;
import org.junit.jupiter.api.Test;
import tech.pegasys.teku.bls.BLSKeyPair;
import tech.pegasys.teku.bls.BLSPublicKey;
import tech.pegasys.teku.bls.BLSSecretKey;

class EciesTest {

  @Test
  void endToEndTestNoSerialisation() {

    // This is the key pair of the recipient of the message
    final BLSKeyPair myKeys = BLSKeyPair.random(12345);

    // The message to encrypt
    final Bytes message = Bytes.wrap("Hello, world!".getBytes(UTF_16));

    // Encrypt the message on the remote side, using receiver's public key
    final EncryptedMessage encryptedMessage = Ecies.encrypt(myKeys.getPublicKey(), message);
    System.out.println(encryptedMessage.toHex());

    // Decryption is done locally using my secret key
    final Bytes decryptedMessage = Ecies.decrypt(myKeys.getSecretKey(), encryptedMessage);
    System.out.println(new String(decryptedMessage.toArray(), UTF_16));

    assertEquals(message, decryptedMessage);
  }

  @Test
  void endToEndTestSerialised() {

    // This is the key pair of the recipient of the message
    final BLSKeyPair myKeys = BLSKeyPair.random(12345);

    // The message to encrypt
    final Bytes message = Bytes.wrap("Hello, world!".getBytes(UTF_16));

    // Encrypt the message on the remote side, using receiver's public key
    final String encryptedMessage = Ecies.encrypt(myKeys.getPublicKey(), message).toHex();
    System.out.println(encryptedMessage);

    // ...encryptedMessage string can be sent in an email or whatever...

    // Decryption is done locally using my secret key
    final Bytes decryptedMessage =
        Ecies.decrypt(myKeys.getSecretKey(), EncryptedMessage.fromHex(encryptedMessage));
    System.out.println(new String(decryptedMessage.toArray(), UTF_16));

    assertEquals(message, decryptedMessage);
  }

  @Test
  void endToEndTestBase64() {

    // The message to be encrypted and sent
    final Bytes message = Bytes.wrap("Hello, world!".getBytes(UTF_16));

    /*
     * The sender has the recipient's public key as a hexadecimal string
     */

    final String publicKeyString =
        "0x81a0584dee1a52473fb7c48addb15c7d1f0508b3b2b62f75d6d2da40002991aa56fef283ebe6d8dbde73e852077a5049";

    // Sender encrypts the message using recipient's public key
    final BLSPublicKey publicKey =
        BLSPublicKey.fromBytesCompressed(Bytes.fromHexString(publicKeyString));
    final String encryptedMessage = Ecies.encrypt(publicKey, message).toBase64();

    /*
     * Now send the encryptedMessage string by email or whatever
     */

    System.out.println(encryptedMessage);

    /*
     * The receiver can now decrypt the message with their secret key
     */

    // Recipient's secret key needs to be retrieved from somewhere
    BLSSecretKey secretKey =
        BLSSecretKey.fromBytes(
            Bytes.fromHexString(
                "0x288e4954608476a30a2eb71cfd7cce7e39a1404aa23cf2ef5a08be34fdb7c149"));
    final Bytes decryptedMessage =
        Ecies.decrypt(secretKey, EncryptedMessage.fromBase64(encryptedMessage));

    System.out.println(new String(decryptedMessage.toArray(), UTF_16));

    assertEquals(message, decryptedMessage);
  }
}
