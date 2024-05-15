import Node1, Node2

# Simple 2 node system, communication using files
# Multi-layer multiplications. Tolerance and result test

# TODO MODIFY NODES AND MAIN TO USE THE SOLID PROXY

def main():
    v1 = [1.0, 2.0, 3.0, 4.0]
    v2 = [12.5, 13.5, 14.5, 15.5]

    # Number of "levels of multiplication" allowed. Higher mult_dept -> Bigger files (and slower operations? #TODO Check)
    # IF THIS IS LOWER THAN THE NUMBER OF MULTIPLICATIONS DONE AN ERROR IS RAISED
    mult_depth = 2

    # The scaling factor is 2^scale_mod_size
    # This value should be approx 20 + desired precision (30 bits in this case). Higher scale size -> Bigger files and slower operations
    scale_mod_size = 50

    # Vector size
    batch_size = 8

    # Example params:
    # multDepth = 5
    # scaleModSize = 40
    # batchSize = 32

    # Step 1
    node1SetupTuple = Node1.node1_setup_encrypt_serialize(v1, v2, mult_depth, scale_mod_size, batch_size)
    cc = node1SetupTuple[0]
    keypair = node1SetupTuple[1]

    # Step 2
    Node2.node2_deserialize_computate_serialize()

    # Step 3
    Node1.node1_deserialize_decrypt_verify(v1, v2, cc, keypair, len(v1))


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    main()

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
