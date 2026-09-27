Public keys (Ed25519, PEM) this build of FR_OS accepts release signatures
from -- one `*.pem` file per key. `frfw.release_signing` refuses every
update while this directory has none. How to create the key pair and
publish a signed release: docs/RELEASING.md.
