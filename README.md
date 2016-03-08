# Pgp Encryption encoder plugin for Embulk

Embulk encoder plugin to encrypt with PGP key.

## Overview

* **Plugin type**: encoder

## Configuration

- **public_key_ring**: KeyRing file path (string, required)
- **key_name**: User ID sub-string of the public key like email (string, default: `""`). If omitted, the first pubKey is used.

## Example

```yaml
out:
  type: file output plugin type
  encoders:
    - type: pgp_encryption
      public_key_ring: ./sample/pubring.gpg
      key_name: mokemokechicken@example.com
```


## Build

```
$ ./gradlew gem  # -t to watch change of files and rebuild continuously
```
