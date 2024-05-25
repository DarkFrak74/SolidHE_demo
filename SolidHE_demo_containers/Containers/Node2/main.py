import time

import Node2

# 2 containers for nodes + container with storage on SolidPod. Intermediate serialization to files is required (python wrapper does not support serialize to streams at this stage)

def main():
    # Step 1
    time.sleep(20)      # Wait for Node1 to encrypt data and store them in the Pod

    # Step 2
    Node2.node2_deserialize_computate_serialize()

    # Step 3

if __name__ == '__main__':
    main()
