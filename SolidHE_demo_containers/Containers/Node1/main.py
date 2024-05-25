import Node1
import time

# 2 containers for nodes + container with storage on SolidPod. Intermediate serialization to files is required (python wrapper does not support serialize to streams at this stage)

def main():
    v1 = [1.0, 2.0, 3.0, 4.0]
    v2 = [12.5, 13.5, 14.5, 15.5]

    # Number of "levels of multiplication" allowed. Higher mult_dept -> Bigger files (and slower operations? #TODO Check)
    # IF THIS IS LOWER THAN THE NUMBER OF MULTIPLICATIONS DONE AN ERROR IS RAISED
    mult_depth = 1

    # The scaling factor is 2^scale_mod_size
    # This value should be approx 20 + desired precision (30 bits in this case). Higher scale size -> Bigger files and slower operations
    scale_mod_size = 50

    # Vector size
    batch_size = 8

    # Example params:
    # multDepth = 5
    # scaleModSize = 40
    # batchSize = 32

    time.sleep(10)

    # Step 1
    node1SetupTuple = Node1.node1_setup_encrypt_serialize(v1, v2, mult_depth, scale_mod_size, batch_size)
    cc = node1SetupTuple[0]
    keypair = node1SetupTuple[1]

    # Step 2
    time.sleep(15)  # Wait for Node2 computations

    # Step 3
    Node1.node1_deserialize_decrypt_verify(v1, v2, cc, keypair, len(v1))

if __name__ == '__main__':
    main()
