# a) symetric:
# GET symetric/key -> zwraca losowo wygenerowany klucz symetryczny w postaci HEXów (może być JSON)
# POST symetric/key -> ustawia na serwerze klucz symetryczny podany w postaci HEX w request
# POST symetric/encode -> wysyłamy wiadomość, w wyniku dostajemy ją zaszyfrowaną
# POST symetric/decode -> wysyłamy wiadomość, w wyniku dostajemy ją odszyfrowaną


from cryptography.fernet import Fernet



class Symmetric():

    def __init__(self) -> None:
        self.key = None

    @staticmethod
    def create_random_key() -> str:

        """Returns a randomly generated symmetric key in the form of HEX"""

        key = Fernet.generate_key()
        return key.hex()

    def set_key(self, key: str) -> None:

        """Sets the symmetric key provided in the form of HEX and prints it's value
              Args:
                  key (str) : Key value
              Returns:
                  Nothing
              """

        self.key = bytearray.fromhex(key)
        print(self.key)

    def encode_message(self, message: str) -> bytes:
        """Encodes message with the key specified on initalization
              Args:
                  message (str): Message to encrypt
              Returns:
                  bytes: HEX encrypted message
              """
        return Fernet(self.key).encrypt(bytes(message, 'utf-8'))

    def decode_message(self, message: str) -> bytes:
        """Decodes message with the key specified on initalization
                Args:
                    message (str): HEX encrypted message
                Returns:
                    bytes: Decrypted message
                """
        return Fernet(self.key).decrypt(bytes(message, 'utf-8'))