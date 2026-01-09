from flask import Flask, render_template, request
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec, dsa, ed25519, ed448
from cryptography.exceptions import InvalidSignature
import datetime

app = Flask(__name__)

def parse_cert(cert_pem):
    try:
        if isinstance(cert_pem, str):
            cert_pem = cert_pem.encode('utf-8')
        return x509.load_pem_x509_certificate(cert_pem, default_backend())
    except Exception as e:
        return None

def parse_certs(certs_pem):
    try:
        if isinstance(certs_pem, str):
            certs_pem = certs_pem.encode('utf-8')
        return x509.load_pem_x509_certificates(certs_pem)
    except Exception as e:
        return []

def get_extensions(cert):
    exts = {}
    try:
        san_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        exts['san'] = [str(n) for n in san_ext.value]
    except x509.ExtensionNotFound:
        pass
        
    try:
        bc_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.BASIC_CONSTRAINTS)
        exts['basic_constraints'] = {
            'ca': bc_ext.value.ca,
            'path_length': bc_ext.value.path_length
        }
    except x509.ExtensionNotFound:
        pass
        
    try:
        ku_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.KEY_USAGE)
        usages = []
        # Check standard usages
        try:
             if ku_ext.value.digital_signature: usages.append('Digital Signature')
        except ValueError: pass
        try:
             if ku_ext.value.content_commitment: usages.append('Content Commitment')
        except ValueError: pass
        try:
             if ku_ext.value.key_encipherment: usages.append('Key Encipherment')
        except ValueError: pass
        try:
             if ku_ext.value.data_encipherment: usages.append('Data Encipherment')
        except ValueError: pass
        try:
             if ku_ext.value.key_agreement: usages.append('Key Agreement')
        except ValueError: pass
        try:
             if ku_ext.value.key_cert_sign: usages.append('Key Cert Sign')
        except ValueError: pass
        try:
             if ku_ext.value.crl_sign: usages.append('CRL Sign')
        except ValueError: pass
        
        exts['key_usage'] = usages
    except x509.ExtensionNotFound:
        pass

    return exts

def get_public_key_info(cert):
    pk = cert.public_key()
    info = "Unknown"
    size = "Unknown"
    
    if isinstance(pk, rsa.RSAPublicKey):
        info = "RSA"
        size = pk.key_size
    elif isinstance(pk, ec.EllipticCurvePublicKey):
        info = "Elliptic Curve"
        size = pk.key_size
    elif isinstance(pk, dsa.DSAPublicKey):
        info = "DSA"
        size = pk.key_size
    elif isinstance(pk, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        info = "EdDSA"
        size = "N/A" # Curve specific
        
    return {"type": info, "size": size}

def get_cert_details(cert):
    if not cert: return None
    
    extensions = get_extensions(cert)
    pk_info = get_public_key_info(cert)
    
    # Try to get signature algorithm name safely
    sig_alg = "Unknown"
    try:
        if cert.signature_hash_algorithm:
            sig_alg = f"{cert.signature_hash_algorithm.name.upper()} (with {cert.signature_algorithm_oid._name if hasattr(cert.signature_algorithm_oid, '_name') else 'Unknown'})"
        else:
             sig_alg = cert.signature_algorithm_oid._name if hasattr(cert.signature_algorithm_oid, '_name') else str(cert.signature_algorithm_oid)
    except:
        sig_alg = str(cert.signature_algorithm_oid)

    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial_number": cert.serial_number,
        "not_valid_before": cert.not_valid_before_utc,
        "not_valid_after": cert.not_valid_after_utc,
        "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
        "version": cert.version.name,
        "signature_algorithm": sig_alg,
        "public_key": pk_info,
        "extensions": extensions
    }

def verify_trust_chain(cert, trusted_certs):
    chain = []
    current_cert = cert
    
    # Avoid infinite loops
    max_depth = 10
    
    # If the user provides a self-signed root in User box and same in CA box, handle that.
    # But generally User box is leaf.
    
    for _ in range(max_depth):
        found_issuer = None
        
        # Check against all trusted certs
        for ca in trusted_certs:
            if ca.subject == current_cert.issuer:
                try:
                    # Verify signature
                    public_key = ca.public_key()
                    public_key.verify(
                        current_cert.signature,
                        current_cert.tbs_certificate_bytes,
                        padding.PKCS1v15(),
                        current_cert.signature_hash_algorithm,
                    )
                    found_issuer = ca
                    break
                except InvalidSignature:
                    continue
                except Exception:
                    continue
        
        if found_issuer:
            chain.append(found_issuer)
            current_cert = found_issuer
            
            # If self-signed, we found a root
            if current_cert.issuer == current_cert.subject:
                return True, chain
        else:
            # Could not find a parent in the trusted list.
            # If chain is not empty, it means we verified at least one link.
            # But is it "Trusted"? 
            # If the user provided [Int], and Leaf verified against Int.
            # And Int issuer (Root) is NOT provided.
            # It is verified against the provided certs.
            if len(chain) > 0:
                 return True, chain
            return False, []
            
    return True, chain

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    user_cert_details = None
    ca_certs_details = [] # List of details
    user_cert_input = ""
    ca_cert_input = ""
    verification_chain_details = []

    if request.method == 'POST':
        user_cert_input = request.form.get('user_cert', '').strip()
        ca_cert_input = request.form.get('ca_cert', '').strip()

        user_cert = parse_cert(user_cert_input)
        ca_certs = parse_certs(ca_cert_input)

        if not user_cert:
            result = {"status": "error", "message": "Invalid User Certificate format."}
        elif not ca_certs:
            user_cert_details = get_cert_details(user_cert)
            result = {"status": "error", "message": "No valid certificates found in CA input."}
        else:
            user_cert_details = get_cert_details(user_cert)
            ca_certs_details = [get_cert_details(c) for c in ca_certs]

            try:
                is_trusted, chain = verify_trust_chain(user_cert, ca_certs)
                
                if is_trusted:
                    result = {"status": "success", "message": f"Certificate is TRUSTED. Chain length: {len(chain)}"}
                    verification_chain_details = [get_cert_details(c) for c in chain]
                else:
                    result = {"status": "failure", "message": "Certificate is NOT trusted by any of the provided CAs."}
            except Exception as e:
                result = {"status": "error", "message": f"Verification error: {str(e)}"}

    return render_template('index.html', 
                           result=result, 
                           user_cert_details=user_cert_details, 
                           ca_certs_details=ca_certs_details,
                           verification_chain_details=verification_chain_details,
                           user_cert_input=user_cert_input,
                           ca_cert_input=ca_cert_input)

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True, port=5001)
