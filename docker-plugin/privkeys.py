#!/usr/bin/env python3

import click

from hashlib import sha3_256
from base64 import b64encode, b64decode

"""
Get a deterministic WireGuard key from a seed (secret) and an string-represented IP address
(non-secret).

This just takes the keccak256 of (seed | additional | ipaddr). Meaning that leaking one or more
private keys + the respective IP addresses shouldn't compromise the seed, as keccak isn't
susceptible from length-extension attacks. This is based on my quite limited understanding of
cryptography. If you need to use this in production, please consult an actual professional working
in the field of cryptography to check that this algorithm is sound for your application.
"""

_DEFAULT_ADDITIONAL = b64encode(b"bestov.io").decode('ascii')

def _ipaddr_to_bytes(ipaddr: str) -> bytes:
  from ipaddress import IPv4Address
  ipaddr_ = IPv4Address(ipaddr.split('/')[0])
  return ipaddr_.packed

# base64-encoded seed and additional, string-formatted IPv4
def derive_privkey(seed: str, ipaddr: str, additional: str = _DEFAULT_ADDITIONAL) -> str:
  return derive_privkey_raw(b64decode(seed), _ipaddr_to_bytes(ipaddr), b64decode(additional))

def derive_privkey_raw(seed: bytes, ipaddr: bytes, additional: bytes) -> str:
  s = sha3_256()
  s.update(seed + additional + ipaddr)
  h = bytearray(s.digest())
  # clamp the result to make it a valid curve25519 key
  h[0] = h[0] & 0b11111000
  h[31] = (h[31] & 0b01111111) | 0b01000000
  return b64encode(h).decode('ascii')

@click.command()
@click.option('--add', default=None, help='Additional base64-encoded value for key derivation')
@click.argument('seed')
@click.argument('ipaddr')
def main(add, seed, ipaddr):
  """Derive a private key for IPADDR using seed SEED, where SEED is base64-encoded."""
  call = {}
  call['seed'] = seed
  call['ipaddr'] = ipaddr
  if (add is not None): call['additional'] = add
  print(derive_privkey(**call))

if __name__ == '__main__':
  main()

