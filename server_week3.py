import socket
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidTag, InvalidSignature

def load_keys():
    """Loads Bob's private identity key and Alice's public identity key."""
    with open("bob_private.pem", "rb") as f:
        bob_priv = serialization.load_pem_private_key(f.read(), password=None)
    with open("alice_public.pem", "rb") as f:
        alice_pub = serialization.load_pem_public_key(f.read())
    return bob_priv, alice_pub

def start_server():
    host, port = '0.0.0.0', 65432
    bob_identity_priv, alice_identity_pub = load_keys()
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        s.listen()
        print(f"[*] Bob (Server) listening on {host}:{port}...")
        
        conn, addr = s.accept()
        with conn:
            # --- PHASE 1: AUTHENTICATED ECDH HANDSHAKE ---
            # 1. Generate Bob's ephemeral X25519PrivateKey
            bob_ephemeral_priv = x25519.X25519PrivateKey.generate()

            # 2. Extract Bob's X25519 public bytes
            bob_pub_bytes = bob_ephemeral_priv.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )

            # 3. Use bob_identity_priv to SIGN the X25519 public bytes using padding.PSS and hashes.SHA256()
            bob_signature = bob_identity_priv.sign(
                bob_pub_bytes,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )

            # 4. Receive Alice's data (Format: 256-byte signature + 32-byte X25519 public key)
            data = conn.recv(288)
            alice_sig = data[:256]
            alice_pub_bytes = data[256:]

            # 5. Use alice_identity_pub to VERIFY Alice's signature against her X25519 public bytes.
            #          (If verification fails, cryptography will raise an InvalidSignature exception. Let it crash the connection.)
            alice_identity_pub.verify(
                alice_sig,
                alice_pub_bytes,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            print("[+] Alice's signature verified.")

            print("[*] Handshake complete. Waiting for payload...")
            
            # 6. Send Bob's signature and Bob's X25519 public bytes to Alice.
            conn.sendall(bob_signature + bob_pub_bytes)

            # 7. Compute the shared_secret using the verified X25519 points.
            alice_ephemeral_pub = x25519.X25519PublicKey.from_public_bytes(alice_pub_bytes)
            shared_secret = bob_ephemeral_priv.exchange(alice_ephemeral_pub)

            # --- PHASE 2: KEY DERIVATION ---
            # Derive the AES key using HKDF (Same as Week 2)
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'handshake data'
            ).derive(shared_secret)

            # --- PHASE 3: RECEIVE PAYLOAD ---
            # Receive and decrypt the AES-GCM payload (Same as Week 1 & 2)
            data = conn.recv(4096)
            if data:
                # Extract nonce, tag, and ciphertext. 
                nonce  = data[:12]
                tag = data[12:28]
                ciphertext = data[28:]

                # Call your Week 1 decrypt_payload() using the NEW derived key.
                try:
                    cipher = Cipher(algorithms.AES(derived_key), modes.GCM(nonce, tag))
                    decryptor = cipher.decryptor()
                    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
                    print(f"[+] Decrypted Message: {plaintext.decode()}")
                except InvalidTag:
                    print("[-] Decryption failed: Invalid tag or key mismatch.")

if __name__ == "__main__":
    start_server()