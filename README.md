# SSH SK Attestation Proxy

## Background

OpenSSH has `-sk` type keys that are designed to be generated and stored on hardware security keys. But, for privacy reasons, there is no way for a server to prove that any `-sk` key is actually stored in hardware and not exportable. Nor is it possible for a server to prove the hardware identity of a security key.

For this prototype project, we embed attestation information into an SSH certificate, so that a server can confirm the residency of the key:

```
id-cert.pub:
        Type: sk-ssh-ed25519-cert-v01@openssh.com user certificate
        Public key: SK-ED25519-CERT SHA256:3zjLLEQv8OELBVQwZLdzSlnqVYxq5aV3nZuqXVHtrzg
        Signing CA: ED25519 SHA256:tZa6QeXJgtjXhBrOhiBsFpZRRBQDB6wzC01HX0i8JnE (using ssh-ed25519)
        Key ID: "key-attestation"
        Serial: 1
        Valid: from 2025-04-28T14:12:18 to 2026-04-28T14:12:18
        Principals:
                carl
        Critical Options: (none)
        Extensions:
                ssh-sk-attest-v01@step.sm AAAAEXAMPLEzaC1zay1hdHRlc3QtdjAxAAAELwAAABFzc2g...
                permit-user-rc
                permit-X11-forwarding
                permit-agent-forwarding
                permit-port-forwarding
                permit-pty
        Signature:
                bd:50:e9:bc:c8:fe:...
```

This project ensures that only hardware-backed and attested SSH certificates can be used to access an OpenSSH server. This could be extended to test attestation information against an inventory of devices that are allowed to SSH.

This could be run on an SSH bastion host (aka SSH jump box), to confirm attestations before passing a connection on to a final host.

There are two binaries:

### Certificate issuer

`ssh_ca_attest` is an SSH user certificate issuer. Given an SSH pubkey and attestation information, it signs an SSH `-sk` certificates with SSH attestation data embedded as a custom extension in the certificate.

Here's an example where we generate certificates with attestation data, using a YubiKey:

```
ssh-keygen -t ed25519 -f ca_key -N ""
curl -sLo ca.pem https://developers.yubico.com/PKI/yubico-piv-ca-1.pem

step crypto rand --format raw  128 > challenge.bin

ssh-keygen -t ed25519-sk -f id -N "" -O challenge=challenge.bin -O write-attestation=attestation.bin
bin/ssh_ca_attest ca_key id.pub attestation.bin challenge.bin "carl" id-cert.pub

ssh-keygen -t ecdsa-sk -f ecdsa_id -N "" -O challenge=challenge.bin -O write-attestation=ecdsa_attestation.bin
bin/ssh_ca_attest ca_key ecdsa_id.pub ecdsa_attestation.bin challenge.bin "carl" ecdsa_id-cert.pub
```

### Server authorization

`verify_ssh_ca_attestation` is the authorization component.

It's designed to run on an SSH server as a global `AuthorizedPrincipalsCommand`.

To verify the attestations in the certificates generated above, we need the Yubico FIDO root CA certificate:

```
curl https://developers.yubico.com/PKI/yubico-fido-ca-1.pem -o yubico-ca.pem
```

Then:

```
bin/verify_ssh_sk_attestation --ca yubico-ca.pem carl $(< id-cert.pub)
bin/verify_ssh_sk_attestation --ca yubico-ca.pem carl $(< ecdsa_id-cert.pub)
```

Both will exit with code 0 on success.
Errors are printed to stderr and logged to the systemd journal, with identifier `verify-ssh-sk`.

#### Configuring SSHD

You can run this as an `AuthorizedPrincipalsCommand`, eg:

```
AuthorizedPrincipalsCommand /bin/verify_ssh_ca_attestation --ca /etc/ssh/yubico-fido-ca.pem %u %t %k
```

Any certificate without an attestation will be rejected.
If a certificate has an attestation, it will be verified.
If the `--ca` flag is passed, the attestation certificate must chain up to the root CA supplied.
The certificate principals are then printed.
(If the certificate has empty principals, the connection is rejected.)

