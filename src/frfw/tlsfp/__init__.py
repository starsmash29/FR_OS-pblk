"""TLS client fingerprinting without decryption (phase 19).

- clienthello: strict parsing of a ClientHello from raw TLS records
- fingerprint: JA3 and JA4 (both BSD 3-Clause methods; JA4+ is not
  implemented, see fingerprint's docstring)
- reassembly: hellos that span several TCP segments
- inventory / daemon: the fr-tls-fp service
"""
