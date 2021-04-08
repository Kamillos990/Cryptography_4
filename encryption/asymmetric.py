# b) asymetric:
# GET asymetric/key -> zwraca nowy klucz publiczny i prywatny w postaci HEX (w JSON jako dict) i ustawia go na serwerze
# GET asymetric/key/ssh -> zwraca klucz publiczny i prywatny w postaci HEX zapisany w formacie OpenSSH
# POST asymetric/key -> ustawia na serwerze klucz publiczny i prywatny w postaci HEX (w JSON jako dict)
# POST asymetric/verify -> korzystając z aktualnie ustawionego klucza prywatnego, podpisuje wiadomość i zwracaą ją podpisaną
# POST asymetric/sign -> korzystając z aktualnie ustawionego klucza publicznego, weryfikuję czy wiadomość była zaszyfrowana przy jego użyciu
# POST asymetric/encode -> wysyłamy wiadomość, w wyniku dostajemy ją zaszyfrowaną
# POST asymetric/decode -> wysyłamy wiadomość, w wyniku dostajemy ją odszyfrowaną


from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import (
    padding, rsa
)

import base64

class Asymmetric():

    def __init__(self):
        self._privateKey = None
        self._publicKey = None

    def serialize_keys(self) -> list:
        """Serializes public and private key in HEX form
                      Args:
                          None
                      Returns:
                          list made of private and public key in HEX form
                      """
        private_pem = self._privateKey.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_pem = self._privateKey.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return [private_pem.hex(), public_pem.hex()]

    def serialize_keys_ssh(self) -> list:
        """Serializes public and private key in HEX form saved in OpenSSH format
                Args:
                     None
                Returns:
                     list made of private and public key in HEX form in OpenSSH format"""
        private_ssh = self._privateKey.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_ssh = self._privateKey.public_key().public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH
        )
        return [private_ssh.hex(), public_ssh.hex()]

    def set_keys(self, private_key, public_key) -> None:
        """Sets the public and private key in the form of HEX (in JSON as dict)
                Args:
                     private_key
                     public_key
                Returns:
                     Nothing"""
        self._privateKey = serialization.load_pem_private_key(
            bytearray.fromhex(private_key),
            password=None,
        )
        self._publicKey = serialization.load_pem_public_key(bytearray.fromhex(public_key))

    def generate_keys(self) -> None:
        """Generates keys, sets for class and returns in OpenSSL format
                Args:
                    None
                Returns:
                    Nothing
                """
        self._privateKey = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self._publicKey = self._privateKey.public_key()

    def sign(self, message: str) -> bytes:
        """Using currently set public key, signs the message and returns it signed
                Args:
                    message (str): Message to sign
                Returns:
                    signed message (bytes)
                """
        return base64.b64encode(self._privateKey.sign(
            bytes(message, "utf-8"),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        )

    def verify(self, message: str, signature: str) -> bool:
        """Verify if the message was signed with given signature
                Args:
                    signature (str): Signature to verify
                    message (str): Message to verify
                """
        decoded_sign = base64.b64decode(signature)
        try:
            self._publicKey.verify(
                decoded_sign,
                bytes(message, "utf-8"),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False

    def encode(self, message: str) -> bytes:
        """Encrypts text with set key
               Args:
                   text (str): Text to encrypt
               Returns:
                   (str): Encrypted text in bytes
               """
        return base64.b64encode(self._publicKey.encrypt(
            bytes(message, "utf-8"),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        )

    def decode(self, message: str) -> str:
        """Decrypts text with set key
                Args:
                    text (str): Hex text to decrypt
                Returns:
                    (str): Decrypted key
                """
        decoded = base64.b64decode(message)
        return self._privateKey.decrypt(
            decoded,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )


