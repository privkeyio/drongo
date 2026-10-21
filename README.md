# Drongo, for Shrike

An unofficial fork of [Drongo](https://github.com/sparrowwallet/drongo), the library [Shrike](https://github.com/privkeyio/shrike) is built on. It follows Bitcoin's change of proof-of-work algorithm to BLAKE2b, signs with the unified opt-in signature hash, and holds a coinbase to the depth the network asks for. It is not affiliated with the Sparrow project.

> **Not audited. Use at your own risk, and no warranty of any kind, see the [Apache 2.0 license](LICENSE).** Everything below the divider is upstream's documentation and describes Drongo rather than this fork.

---

# Drongo

Drongo is a Java Bitcoin library built mainly to support [Sparrow Wallet](https://sparrowwallet.com).

## Building

Drongo can be built with

`./gradlew jar`

## License

Drongo is licensed under the Apache 2 software licence.

## Credits

Drongo was inspired by (and is in part derived from) the [bitcoinj](https://bitcoinj.org) Bitcoin library.
