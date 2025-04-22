# SSH SK Attestation Proxy

## Background

OpenSSH has `-sk` type keys that are designed to be generated and stored on hardware security keys. But, for privacy reasons, there is no way for a server to prove that any `-sk` key is actually stored in hardware and not exportable. In this project, we embed attestation information into an SSH certificate, so that a server can confirm the residency of the key and reject any non-attested keys.

This prototype project ensures that only hardware-backed and attested SSH certificates can be used to access an OpenSSH server.

This could be run on an SSH bastion host (aka SSH jump box), to confirm attestations before passing a connection on to a final host.

There are two binaries:

### Certificate issuer

`ssh_ca_attest` is an SSH user certificate issuer. Given an SSH pubkey and attestation information, it signs an SSH `-sk` certificates with SSH attestation data embedded as a custom extension in the certificate.

To generate a certificate with attestation data:

```
ssh-keygen -t ed25519 -f ca_key -N ""
curl -sLo ca.pem https://developers.yubico.com/PKI/yubico-piv-ca-1.pem

step crypto rand --format raw  128 > challenge.bin

ssh-keygen -t ed25519-sk -f id -N "" -O challenge=challenge.bin -O write-attestation=attestation.bin
bin/ssh_ca_attest ca_key id.pub attestation.bin challenge.bin "carl" id-cert.pub
bin/verify_ssh_sk_attestation --ca ca.pem carl $(cat id-cert.pub)

ssh-keygen -t ecdsa-sk -f ecdsa_id -N "" -O challenge=challenge.bin -O write-attestation=ecdsa_attestation.bin
bin/ssh_ca_attest ca_key ecdsa_id.pub ecdsa_attestation.bin challenge.bin "carl" ecdsa_id-cert.pub
bin/verify_ssh_sk_attestation --ca ca.pem carl $(cat ecdsa_id-cert.pub)
```

### Server authorization

`verify_ssh_ca_attestation` is the authorization component. It's designed to run on an SSH server as a global `AuthorizedPrincipalsCommand`, eg.

```
AuthorizedPrincipalsCommand /bin/verify_ssh_ca_attestation %u %t %k
```

Any certificate without an attestation will be rejected.
If a certificate has an attestation, it will be verified.
The certificate principals are then printed.
(If the certificate has empty principals, the connection is rejected.)

