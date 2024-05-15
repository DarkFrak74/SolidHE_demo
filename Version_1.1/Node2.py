import openfhe

# FILES PATH DEFINITION

# Save-Load locations for keys
datafolder = 'demoData'
ccLocation = '/cryptocontext.txt'
pubKeyLocation = '/key_pub.txt'  # Pub key
multKeyLocation = '/key_mult.txt'  # relinearization key
rotKeyLocation = '/key_rot.txt'  # automorphism / rotation key

# Save-load locations for RAW ciphertexts
cipherOneLocation = '/ciphertext1.txt'
cipherTwoLocation = '/ciphertext2.txt'

# Save-load locations for evaluated ciphertexts
cipherMultLocation = '/ciphertextMult.txt'
cipherMult3Location = '/ciphertextMult3.txt'
cipherAddLocation = '/ciphertextAdd.txt'
cipherRotLocation = '/ciphertextRot.txt'
cipherRotNegLocation = '/ciphertextRotNegLocation.txt'


# Demarcate - Visual separator between the sections of code
def demarcate(msg):
    print("**************************************************")
    print(msg)
    print("**************************************************\n")

###
# node2_deserialize_computate_serialize
#  - deserialize data from a file which simulates receiving data from node1
#  - process data by doing operations
#  - Serialize the result
###

def node2_deserialize_computate_serialize():
    demarcate("Part 2a: Cryptocontext and data deserialization (Node 2)")

    node2CC, res = openfhe.DeserializeCryptoContext(datafolder + ccLocation, openfhe.BINARY)
    if not res:
        raise Exception(f"I cannot deserialize the cryptocontext from {datafolder + ccLocation}")

    print("Node2: Deserialized CryptoContex")

    '''
    # Node2 does NOT have a secret key. It has only access to the public key # TODO CHECK IF NEEDED
    node2PublicKey, res = openfhe.DeserializePublicKey(mydatafolder + pubKeyLocation, openfhe.BINARY)
    if not res:
        raise Exception(f"I cannot deserialize the public key from {mydatafolder + pubKeyLocation}")
    print("Node2: Public Key deserialized\n")
    '''

    if not node2CC.DeserializeEvalMultKey(datafolder + multKeyLocation, openfhe.BINARY):
        raise Exception(f"Cannot deserialize eval mult keys from {datafolder + multKeyLocation}")
    print("Node2: Deserialized eval mult keys\n")

    if not node2CC.DeserializeEvalAutomorphismKey(datafolder + rotKeyLocation, openfhe.BINARY):
        raise Exception(f"Cannot deserialize eval automorphism keys from {datafolder + rotKeyLocation}")

    node2C1, res = openfhe.DeserializeCiphertext(datafolder + cipherOneLocation, openfhe.BINARY)
    if not res:
        raise Exception(f"Cannot deserialize the ciphertext from {datafolder + cipherOneLocation}")
    print("Node2: Deserialized ciphertext 1\n")

    node2C2, res = openfhe.DeserializeCiphertext(datafolder + cipherTwoLocation, openfhe.BINARY)
    if not res:
        raise Exception(f"Cannot deserialize the ciphertext from {datafolder + cipherTwoLocation}")
    print("Node2: Deserialized ciphertext 2\n")

    demarcate("Part 2b: Computation (Node 2)")

    # C1*C2
    node2CiphertextMult = node2CC.EvalMult(node2C1, node2C2)

    # C1*C1*C2
    node2CiphertextMult3 = node2CC.EvalMult(node2C1, node2CiphertextMult)

    # C1+C2
    node2CiphertextAdd = node2CC.EvalAdd(node2C1, node2C2)

    # rot 1 C1
    node2CiphertextRot = node2CC.EvalRotate(node2C1, 1)

    # rot -1 C1
    node2CiphertextRotNeg = node2CC.EvalRotate(node2C1, -1)


    # Node 2 serialize the result of the computation, to send it back to Node 1
    demarcate("Part 2c: Serialization of data that has been operated on (Node 2)")

    openfhe.SerializeToFile(datafolder + cipherMultLocation, node2CiphertextMult, openfhe.BINARY)
    openfhe.SerializeToFile(datafolder + cipherMult3Location, node2CiphertextMult3, openfhe.BINARY)
    openfhe.SerializeToFile(datafolder + cipherAddLocation, node2CiphertextAdd, openfhe.BINARY)
    openfhe.SerializeToFile(datafolder + cipherRotLocation, node2CiphertextRot, openfhe.BINARY)
    openfhe.SerializeToFile(datafolder + cipherRotNegLocation, node2CiphertextRotNeg, openfhe.BINARY)

    print("Serialized all ciphertexts from client\n")
