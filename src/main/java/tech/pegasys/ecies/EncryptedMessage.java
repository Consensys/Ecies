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

import java.util.Base64;
import java.util.Objects;
import org.apache.tuweni.bytes.Bytes;
import tech.pegasys.teku.bls.BLSPublicKey;

public class EncryptedMessage {

  static EncryptedMessage fromBytes(Bytes b) {
    // Need at least 48 pubkey + 12 nonce bytes
    if (b.size() < 60) {
      throw new IllegalArgumentException("Input is too short");
    }
    Bytes pointBytes = b.slice(0, 48);
    Bytes nonceBytes = b.slice(48, 12);
    Bytes messageBytes = b.slice(60);

    return new EncryptedMessage(
        BLSPublicKey.fromBytesCompressed(pointBytes), nonceBytes, messageBytes);
  }

  static EncryptedMessage fromHex(String s) {
    return fromBytes(Bytes.fromHexString(s));
  }

  static EncryptedMessage fromBase64(String b64) {
    Bytes decodedBytes = Bytes.wrap(Base64.getDecoder().decode(b64));
    return fromBytes(decodedBytes);
  }

  private BLSPublicKey publicKey;
  private Bytes nonce;
  private Bytes cipherText;

  public EncryptedMessage(BLSPublicKey publicKey, Bytes nonce, Bytes cipherText) {
    setPublicKey(publicKey);
    setNonce(nonce);
    setCipherText(cipherText);
  }

  public String toHex() {
    return publicKey.toBytesCompressed().toHexString()
        + nonce.toUnprefixedHexString()
        + cipherText.toUnprefixedHexString();
  }

  public String toBase64() {
    final Bytes theBytes = Bytes.wrap(publicKey.toBytesCompressed(), nonce, cipherText);
    return Base64.getEncoder().encodeToString(theBytes.toArray());
  }

  public BLSPublicKey getPublicKey() {
    return publicKey;
  }

  public void setPublicKey(BLSPublicKey publicKey) {
    this.publicKey = publicKey;
  }

  public Bytes getNonce() {
    return nonce;
  }

  public void setNonce(Bytes nonce) {
    this.nonce = nonce;
  }

  public Bytes getCipherText() {
    return cipherText;
  }

  public void setCipherText(Bytes cipherText) {
    this.cipherText = cipherText;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    EncryptedMessage that = (EncryptedMessage) o;
    return publicKey.equals(that.publicKey)
        && nonce.equals(that.nonce)
        && cipherText.equals(that.cipherText);
  }

  @Override
  public int hashCode() {
    return Objects.hash(publicKey, nonce, cipherText);
  }
}
