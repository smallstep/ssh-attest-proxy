# SSH SK Attestation System

This prototype project ensures that only hardware-backed and attested SSH certificates can be used to access an OpenSSH server.

This could be run on an SSH bastion host (aka SSH jump box), to confirm attestations before passing a connection on to a final host.

There are two binaries:

### Certificate issuer

`ssh_ca_attest` is an SSH user certificate issuer. Given an SSH pubkey and attestation information, it signs an SSH `-sk` certificates with SSH attestation data embedded as a custom extension in the certificate.

To generate a certificate with attestation data:

```
ssh-keygen -t ed25519 -f ca_key -N ""

openssl rand 128 > challenge.bin
ssh-keygen -t ed25519-sk -f id -N "" -O challenge=challenge.bin -O write-attestation=attestation.bin

bin/ssh_ca_attest ca_key id.pub attestation.bin challenge.bin "carl" id-cert.pub
```

### Server authorization

`verify_ssh_ca_attestation` is the authorization component. It's designed to run on an SSH server as a global `AuthorizedPrincipalsCommand`, eg.

```
AuthorizedPrincipalsCommand /bin/verify_ssh_ca_attestation %u %k
```

Any certificate without an attestation will be rejected.
If a certificate has an attestation, it will be verified.
The certificate principals are then printed.
(If the certificate has empty principals, the connection is rejected.)

