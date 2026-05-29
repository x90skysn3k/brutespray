# Bad-keys bundle sources

This package vendors known-compromised SSH client private keys from:

- [Rapid7/ssh-badkeys](https://github.com/rapid7/ssh-badkeys) (MIT) — vendor default keys for F5 BIG-IP, ExaGrid, Ceragon FibeAir, Monroe DASDEC, Barracuda, Array Networks, Loadbalancer.org, Quantum DXi
- [HashiCorp Vagrant insecure key](https://github.com/hashicorp/vagrant/tree/main/keys) (MIT) — default Vagrant VM identity

Only Rapid7's `authorized/` directory (client identities found in real-world
`authorized_keys` files) is mirrored here. The `host/` directory (SSH server
identity keys extracted from firmware) is intentionally excluded — host keys
are not usable for client-side authentication.

Refreshed via the same monthly cadence as `wordlist/` updates.
