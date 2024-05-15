import openfhe
import numpy as np

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
#  node1SetupEncryptSerialize
#  - Setup Crypto Context
#  - Encrypt data
#  - Serialize data to files
# @params v1,v2,Key generation parameters
# @return
#  2-tuple of generated CryptoContext, Keypair
##
def node1_setup_encrypt_serialize(v1,v2, multDepth, scaleModSize, batchSize):
    demarcate("Part 1a: CryptoContext generation (Node 1)")

    # CryptoContex CKKS parameters definition
    parameters = openfhe.CCParamsCKKSRNS()
    parameters.SetMultiplicativeDepth(multDepth)
    parameters.SetScalingModSize(scaleModSize)
    parameters.SetBatchSize(batchSize)

    # CryptoContext generation
    node1CC = openfhe.GenCryptoContext(parameters)

    # CryptoContext features enabling
    node1CC.Enable(openfhe.PKE)
    node1CC.Enable(openfhe.KEYSWITCH)
    node1CC.Enable(openfhe.LEVELEDSHE)

    print("Node1: Cryptocontext generated")

    # KeyPair generation
    node1KP = node1CC.KeyGen()
    print("Node1: Keypair generated")

    # Multiplication key generation
    node1CC.EvalMultKeyGen(node1KP.secretKey)
    print("Node1: Eval Mult Keys/ Relinearization keys have been generated")

    # Rotation key generation (for fixed positions)
    node1CC.EvalRotateKeyGen(node1KP.secretKey, [1, 2, -1, -2])
    print("Node1: Rotation keys generated")

    demarcate("Part 1b: Data packing and encryption (Node 1)")

    print("\nNode1: Displaying first data vector: ")
    print(v1)
    print("\n")

    # Vector packing into FHE plaintexts
    node1P1 = node1CC.MakeCKKSPackedPlaintext(v1)
    node1P2 = node1CC.MakeCKKSPackedPlaintext(v2)

    print("Plaintext version of first vector: " + str(node1P1))

    print("Plaintexts have been generated from complex-double vectors")

    # Encryption of plaintexts into ciphertexts
    node1C1 = node1CC.Encrypt(node1KP.publicKey, node1P1)
    node1C2 = node1CC.Encrypt(node1KP.publicKey, node1P2)

    print("Ciphertexts have been generated from plaintexts")

    ###
    #    Part 1c:
    #    We serialize the following:
    #      Cryptocontext
    #      Public key
    #      relinearization (eval mult keys)
    #      rotation keys
    #      Some of the ciphertext
    #
    #      We serialize all of them to files
    ###
    demarcate("Part 1c: Data Serialization (Node 1)")

    if not openfhe.SerializeToFile(datafolder + ccLocation, node1CC, openfhe.BINARY):
        raise Exception("Exception writing cryptocontext to cryptocontext.txt")
    print("Cryptocontext serialized")

    if not openfhe.SerializeToFile(datafolder + pubKeyLocation, node1KP.publicKey, openfhe.BINARY):
        raise Exception("Exception writing public key to pubkey.txt")
    print("Public key has been serialized")

    if not node1CC.SerializeEvalMultKey(datafolder + multKeyLocation, openfhe.BINARY):
        raise Exception("Error writing eval mult keys")
    print("EvalMult/ relinearization keys have been serialized")

    if not node1CC.SerializeEvalAutomorphismKey(datafolder + rotKeyLocation, openfhe.BINARY):
        raise Exception("Error writing rotation keys")
    print("Rotation keys have been serialized")

    if not openfhe.SerializeToFile(datafolder + cipherOneLocation, node1C1, openfhe.BINARY):
        raise Exception("Error writing ciphertext 1")

    if not openfhe.SerializeToFile(datafolder + cipherTwoLocation, node1C2, openfhe.BINARY):
        raise Exception("Error writing ciphertext 2")

    return (node1CC, node1KP)



###
#  node1DeserializeDecryptVerify
#  - deserialize data from the client.
#  - Verify that the results are as we expect
# @params v1,v2 vectors for result verification
# @param cc cryptocontext that was previously generated
# @param kp keypair that was previously generated
# @param vectorSize vector size of the vectors supplied
# @return
#  5-tuple of the plaintexts of various operations
##
def node1_deserialize_decrypt_verify(v1,v2,cc, kp, vectorSize):
    demarcate("Part 3a: Result deserialization (Node 1)")
    node1CiphertextFromNode2_Mult, res = openfhe.DeserializeCiphertext(datafolder + cipherMultLocation, openfhe.BINARY)
    node1CiphertextFromNode2_Mult3, res = openfhe.DeserializeCiphertext(datafolder + cipherMult3Location, openfhe.BINARY)
    node1CiphertextFromNode2_Add, res = openfhe.DeserializeCiphertext(datafolder + cipherAddLocation, openfhe.BINARY)
    node1CiphertextFromNode2_Rot, res = openfhe.DeserializeCiphertext(datafolder + cipherRotLocation, openfhe.BINARY)
    node1CiphertextFromNode2_RotNeg, res = openfhe.DeserializeCiphertext(datafolder + cipherRotNegLocation, openfhe.BINARY)
    print("Deserialized all data from client on server\n")


    demarcate("Part 3b: Result Decryption (Node 1)")

    node1PlaintextFromNode2_Mult = cc.Decrypt(kp.secretKey, node1CiphertextFromNode2_Mult)
    node1PlaintextFromNode2_Mult3 = cc.Decrypt(kp.secretKey, node1CiphertextFromNode2_Mult3)
    node1PlaintextFromNode2_Add = cc.Decrypt(kp.secretKey, node1CiphertextFromNode2_Add)
    node1PlaintextFromNode2_Rot = cc.Decrypt(kp.secretKey, node1CiphertextFromNode2_Rot)
    node1PlaintextFromNode2_RotNeg = cc.Decrypt(kp.secretKey, node1CiphertextFromNode2_RotNeg)

    # Set the correct vector size
    node1PlaintextFromNode2_Mult.SetLength(vectorSize)
    node1PlaintextFromNode2_Mult3.SetLength(vectorSize)
    node1PlaintextFromNode2_Add.SetLength(vectorSize)

    # Size 5 instead of 4 to display rotation
    node1PlaintextFromNode2_Rot.SetLength(vectorSize + 1)
    node1PlaintextFromNode2_RotNeg.SetLength(vectorSize + 1)

    demarcate("Part 3c: Result Verification (Node 1)")
    v1_np = np.array(v1)
    v2_np = np.array(v2)
    print(f"v1: {v1_np}")
    print(f"v2: {v2_np}")

    expected_sum = v1_np + v2_np
    print(f"Sum: EXPECTED = {expected_sum} ACTUAL = {node1PlaintextFromNode2_Add}")

    expected_mult = v1_np * v2_np
    print(f"Mult: EXPECTED = {expected_mult} ACTUAL = {node1PlaintextFromNode2_Mult}")

    expected_mult3 = v1_np * v1_np * v2_np
    print(f"Mult3: EXPECTED = {expected_mult3} ACTUAL = {node1PlaintextFromNode2_Mult3}")

    print("Displaying 5 elements of a 4-element vector to illustrate rotation")
    expected_rot = [v1[1],v1[2],v1[3],"noise","noise"]
    print(f"Rot: EXPECTED = {expected_rot} ACTUAL = {node1PlaintextFromNode2_Rot}")

    expected_rot_neg = [ "noise", v1[0],v1[1], v1[2], v1[3],]
    print(f"Rot: EXPECTED = {expected_rot_neg} ACTUAL = {node1PlaintextFromNode2_RotNeg}")