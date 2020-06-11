# ECIES

This is demo code for implementing [ECIES](https://en.wikipedia.org/wiki/Integrated_Encryption_Scheme) using primitives from Ethereum 2.0.

In short:
  - The sender uses the recipient's Eth2 public key to generate a shared secret
  - The message is encrypted with AES/GCM using a key derived from the shared secret
  - The recipient's private key is used to regenerate the shared secret and decrypt the message

See test case `endToEndTestBase64` for a full example of how this can be used in practice.

## Notes

  - This is simply demo code. It comes with no guarantees whatsoever.
