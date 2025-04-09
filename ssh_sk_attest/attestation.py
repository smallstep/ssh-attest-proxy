import sys
import requests
from base64 import b64decode
from struct import unpack
from hashlib import sha256
from typing import Tuple, Optional, Union
import os

from fido2 import cbor, mds3, webauthn, cose
from cryptography import x509, exceptions
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import ed25519

from dataclasses import dataclass
from typing import Optional, Dict, Any

@dataclass
class AttestationResult:
    valid: bool
    error: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None 

# Get the path to the built-in mds.jwt file
MDS_FILE = os.path.join(os.path.dirname(__file__), 'mds.jwt')
MDS_CA = b64decode(
    """
MIIDXzCCAkegAwIBAgILBAAAAAABIVhTCKIwDQYJKoZIhvcNAQELBQAwTDEgMB4G
A1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjMxEzARBgNVBAoTCkdsb2JhbFNp
Z24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMDkwMzE4MTAwMDAwWhcNMjkwMzE4
MTAwMDAwWjBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMzETMBEG
A1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCASIwDQYJKoZI
hvcNAQEBBQADggEPADCCAQoCggEBAMwldpB5BngiFvXAg7aEyiie/QV2EcWtiHL8
RgJDx7KKnQRfJMsuS+FggkbhUqsMgUdwbN1k0ev1LKMPgj0MK66X17YUhhB5uzsT
gHeMCOFJ0mpiLx9e+pZo34knlTifBtc+ycsmWQ1z3rDI6SYOgxXG71uL0gRgykmm
KPZpO/bLyCiR5Z2KYVc3rHQU3HTgOu5yLy6c+9C7v/U9AOEGM+iCK65TpjoWc4zd
QQ4gOsC0p6Hpsk+QLjJg6VfLuQSSaGjlOCZgdbKfd/+RFO+uIEn8rUAVSNECMWEZ
XriX7613t2Saer9fwRPvm2L7DWzgVGkWqQPabumDk3F2xmmFghcCAwEAAaNCMEAw
DgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFI/wS3+o
LkUkrk1Q+mOai97i3Ru8MA0GCSqGSIb3DQEBCwUAA4IBAQBLQNvAUKr+yAzv95ZU
RUm7lgAJQayzE4aGKAczymvmdLm6AC2upArT9fHxD4q/c2dKg8dEe3jgr25sbwMp
jjM5RcOO5LlXbKr8EpbsU8Yt5CRsuZRj+9xTaGdWPoO4zzUhw8lo/s7awlOqzJCK
6fBdRoyV3XpYKBovHd7NADdBj+1EbddTKJd+82cEHhXXipa0095MJ6RMG3NzdvQX
mcIfeg7jLQitChws/zyrVQ4PkX4268NXSb7hLi18YIvDQVETI53O9zJrlAGomecs
Mx86OyXShkDOOyyGeMlhLxS67ttVb9+E7gUJTb0o2HLO02JQZR7rkpeDMdmztcpH
WD9f"""
)

# read a list of type-lenght-value triplets from binary data
def tlvs(data):
    while data:
        t, l = unpack('>hh', data[:4])
        assert t == 0
        v = data[4:4+l]
        data = data[4+l:]
        yield v

def parse_attestation(s: bytes) -> dict:
    """Parse SSH attestation file format.
    
    Args:
        s: Raw attestation data
        
    Returns:
        dict containing version, certificate, signature, and authData
    """
    version, certificate, signature, authData, reserved_flags, reserved_string = tlvs(s)
    version = str(version, 'utf-8')
    assert version == 'ssh-sk-attest-v01'
    certificate = x509.load_der_x509_certificate(certificate)
    authData = cbor.decode(authData)
    assert reserved_flags == b''
    assert reserved_string == b''
    return dict(version=version, certificate=certificate, signature=signature, authData=authData)

def verify_attestation_signature(attestation: dict, challenge: bytes) -> None:
    """Verify the attestation signature.
    
    Args:
        attestation: Parsed attestation data
        challenge: Challenge bytes used during key generation
    """
    authData = attestation['authData']
    clientDataHash = sha256(challenge).digest()
    signedData = b''.join([authData, clientDataHash])
    signature = attestation['signature']
    attestation_certificate = attestation['certificate']
    assert isinstance(attestation_certificate.public_key(), ec.EllipticCurvePublicKey)
    attestation_certificate.public_key().verify(signature, signedData, ec.ECDSA(hashes.SHA256()))

def verify_attestation_u2f(attestation: dict, challenge: bytes) -> None:
    """Verify U2F attestation signature.
    
    Args:
        attestation: Parsed attestation data
        challenge: Challenge bytes used during key generation
    """
    authData = webauthn.AuthenticatorData(attestation['authData'])
    credentialData = authData.credential_data
    key = b''.join([b'\04', credentialData.public_key[-2], credentialData.public_key[-3]])
    signedData = b''.join([b'\00', authData.rp_id_hash, sha256(challenge).digest(), credentialData.credential_id, key])
    signature = attestation['signature']
    attestation_certificate = attestation['certificate']
    assert isinstance(attestation_certificate.public_key(), ec.EllipticCurvePublicKey)
    attestation_certificate.public_key().verify(signature, signedData, ec.ECDSA(hashes.SHA256()))

def parse_pubkey(key: str) -> Tuple[str, bytes]:
    """Parse SSH public key.
    
    Args:
        key: SSH public key string
        
    Returns:
        Tuple of (key_type, public_key_bytes)
    """
    key_type, pubkey, *_ = key.split(" ")
    key_bytes = b64decode(pubkey)
    match key_type:
        case 'sk-ecdsa-sha2-nistp256@openssh.com':
            (kt, curve_name, ec_point, *application) = tlvs(key_bytes)
            assert str(kt, 'utf-8') == key_type
            publicKey = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), ec_point)
            return key_type, cose.ES256.from_cryptography_key(publicKey)
        case 'sk-ssh-ed25519@openssh.com':
            (kt, pk, *application) = tlvs(key_bytes)
            assert str(kt, 'utf-8') == key_type
            publicKey = ed25519.Ed25519PublicKey.from_public_bytes(pk)
            return key_type, cose.EdDSA.from_cryptography_key(publicKey)
        case _:
            raise Exception('unsupported SSH key type')

def verify_attestation(
    pubkey: Union[str, bytes],
    attestation: bytes,
    challenge: bytes
) -> AttestationResult:
    """Verify SSH key attestation.
    
    Args:
        pubkey: SSH public key string or bytes
        attestation: Raw attestation data
        challenge: Challenge bytes used during key generation
        
    Returns:
        AttestationResult indicating success or failure
    """
    try:
        # Parse files
        if isinstance(pubkey, bytes):
            pubkey = pubkey.decode('utf-8')
            
        attestation_data = parse_attestation(attestation)
            
        # Verify attestation signature
        try:
            verify_attestation_signature(attestation_data, challenge)
        except (AssertionError, exceptions.InvalidSignature):
            try:
                verify_attestation_u2f(attestation_data, challenge)
            except (AssertionError, exceptions.InvalidSignature):
                return AttestationResult(valid=False, error="Invalid attestation signature")
                
        # Match public keys
        key_type, parsed_pubkey = parse_pubkey(pubkey)
        credential_data = webauthn.AuthenticatorData(attestation_data['authData']).credential_data
        if credential_data.public_key != parsed_pubkey:
            return AttestationResult(valid=False, error="Public key mismatch")
            
        # Validate attestation certificate using built-in MDS file
        try:
            attestation_certificate = attestation_data['certificate']
            metadata = mds3.parse_blob(open(MDS_FILE, 'rb').read(), MDS_CA)
            metadata_entry = mds3.MdsAttestationVerifier(metadata).find_entry_by_aaguid(credential_data.aaguid)
            if metadata_entry:
                issuers = [x509.load_der_x509_certificate(cert, default_backend()) 
                         for cert in metadata_entry.metadata_statement.attestation_root_certificates]
                trusted = False
                for cert in issuers:
                    if cert.subject == attestation_certificate.issuer:
                        attestation_certificate.verify_directly_issued_by(cert)
                        trusted = True
                if not trusted:
                    return AttestationResult(valid=False, error="Untrusted attestation certificate")
            else:
                return AttestationResult(valid=False, error="No metadata entry found")
        except Exception as e:
            return AttestationResult(valid=False, error=f"Certificate validation error: {str(e)}")
            
        return AttestationResult(valid=True, metadata={
            'key_type': key_type,
            'aaguid': credential_data.aaguid
        })
        
    except Exception as e:
        return AttestationResult(valid=False, error=str(e)) 