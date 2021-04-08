from fastapi import FastAPI
from encryption.symmetric import Symmetric
from encryption.asymmetric import Asymmetric
from models.Message import Message
from models.SignedMessage import SignedMessage



app = FastAPI()
symetric = Symmetric()
asymmetric = Asymmetric()

# Symmetric


@app.get("/")
def read_root():



    return {"Hello": "World"}


@app.get("/symetric/key")
def get_key():

    """Returns a randomly generated symmetric key in the form of HEX"""

    return Symmetric.create_random_key()


@app.post("/symetric/key")
def post_key(key: str):

    """Sets the symmetric key provided in the form of HEX in request on the server"""

    symetric.set_key(key=key)
    return {"info": "ok"}


@app.post("/symetric/encode")
async def post_symmetric_encode(message: Message):

    """Sends a message and as a result returns it encrypted"""

    return {"encrypted_message": symetric.encode_message(message.message)}


@app.post("/symetric/decode")
async def post_symmetric_decode(message: Message):

    """Sends a message and as a result returns it decrypted"""

    return {"decoded_message": symetric.decode_message(message.message)}

# Asymmetric

@app.get("/asymmetric/key")
async def get_asymmetric_keys():

    """Returns new public and private key in the form of HEX (in JSON as dict) and sets it on the server"""

    asymmetric.generate_keys()
    keys = asymmetric.serialize_keys()
    return {"Private Key": keys[0], "Public Key:": keys[1]}


@app.get("/asymmetric/key/ssh")
async def get_asymmetric_keys_ssh():

    """Returns public and private key in HEX format saved in OpenSSH format"""

    keys = asymmetric.serialize_keys_ssh()
    return {"Private SSH Key": keys[0], "Public SSH Key:": keys[1]}


@app.post("/asymmetric/key")
async def post_asymmetric_keys(private_key, public_key):

    """Sets the public and private key in the form of HEX (in JSON as dict)"""

    asymmetric.set_keys(private_key, public_key)
    return {"Info": "Keys have been set"}


@app.post("/asymmetric/sign")
async def post_asymmetric_sing_message(msg: Message):

    """Using the currently set private key, signs the message and returns it with the signed one"""

    signed_message = asymmetric.sign(msg.message)
    return {"Signed Message": signed_message}


@app.post("/asymmetric/verify")
async def post_asymmetric_sing_message(msg: SignedMessage):

    """Using the currently set public key, verify if the message was encrypted with it"""

    verification = asymmetric.verify(msg.message, msg.signature)
    return {"Sign verification": verification}


@app.post("/asymmetric/encode")
async def post_asymmetric_encode_message(msg: Message):

    """Sends a message and as a result returns it encrypted"""

    encoded_message = asymmetric.encode(msg.message)
    return {"Encoded message": encoded_message}


@app.post("/asymmetric/decode")
async def post_asymmetric_decode_message(msg: Message):

    """Sends a message and as a result returns it decrypted"""

    decoded_message = asymmetric.decode(msg.message)
    return {"Decoded message": decoded_message}
