import os
import hashlib
from fastecdsa import keys, curve

class NybergRueppel:
    def __init__(self, curve):
        # Initializes the curve to be used for key generation and signing
        self.curve = curve

    def generate_keys(self):
        # Generates a private-public key pair
        self.private_key, self.public_key = keys.gen_keypair(self.curve)

    def sign(self, message):
        # Signs a message using the Nyberg-Rueppel signature scheme
        hash_message = int(hashlib.sha256(message.encode()).hexdigest(), 16)
        k = int.from_bytes(os.urandom(32), byteorder='big') # Random number for signature

        while True:
            point = k * self.curve.G # Point on the curve
            r = point.x % self.curve.q 
            if r == 0:
                # Regenerate random number if r is 0
                k = int.from_bytes(os.urandom(32), byteorder='big')
                continue
            # Calculate signature
            s = (hash_message + r * self.private_key) * pow(k, -1, self.curve.q) % self.curve.q
            if s == 0:
                # Regenerate random number if s is 0
                k = int.from_bytes(os.urandom(32), byteorder='big')
                continue
            break

        return r, s

    def verify(self, message, signature):
        # Verifies the signature of a message
        r, s = signature
        # Check if r and s are in the correct interval
        if r < 1 or r > self.curve.q - 1 or s < 1 or s > self.curve.q - 1:
            return False
        # Hash the message again to verify the signature
        hash_message = int(hashlib.sha256(message.encode()).hexdigest(), 16)
        # Calculate the inverse of s mod q
        w = pow(s, -1, self.curve.q)
        u1 = (hash_message * w) % self.curve.q
        u2 = (r * w) % self.curve.q
        point = u1 * self.curve.G + u2 * self.public_key
        # Check if the signature is valid
        if r == point.x % self.curve.q:
            return True
        return False

if __name__ == "__main__":
    message = "Hello, Nyberg-Rueppel!"

    nr = NybergRueppel(curve.P256) # Initialize with the P-256 curve
    nr.generate_keys() # Generate private-public key pair

    signature = nr.sign(message) # Sign the message
    print("Signature: ", signature)

    verification = nr.verify(message, signature) # Verify the signature
    print("Verification: ", verification)
