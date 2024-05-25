import requests

server_url = "http://localhost:3000"
pod_name = "SolidHE-pod"
workspace_name = "SolidHE-demo"

base_url = f"{server_url}/{pod_name}/{workspace_name}"

# TODO Change behaviour to a consistent one when it comes to exception handling (raise exceptions in both methods)

# Reads local data from local_folder/file_name and write them to server/pod/pod_folder/file_name
def write_data_to_pod(pod_folder, local_folder, file_name):
    remote_url = f"{base_url}/{pod_folder}/{file_name}"

    # Stream of local file (instead of reading the whole file)
    with open(f"{local_folder}/{file_name}", "rb") as file:
        response = requests.put(remote_url, data=file, headers={'Content-Type': 'application/binary'})
    print(response.text)
    return response.ok


# Reads remote data from server/pod/pod_folder/file_name and write them to local_folder/file_name
def read_data_from_pod(pod_folder, local_folder, file_name):
    remote_url = f"{base_url}/{pod_folder}/{file_name}"

    # Get the response as a stream
    with requests.get(remote_url, stream=True) as response:
        response.raise_for_status()
        # Write the response to local fine in chunks
        with open(f"{local_folder}/{file_name}", "wb") as file:
            for chunk in response.iter_content(chunk_size=8192):
                file.write(chunk)

        return response.ok

def resources_deleter(folder, resources_list):
    for resource in resources_list:
        print(f"{base_url}/{folder}/{resource}")
        print(requests.delete(f"{base_url}/{folder}/{resource}").status_code)
    print(f"{base_url}/{folder}")
    print(requests.delete(f"{base_url}/{folder}/").status_code)

#resources_deleter("Node1", ["ciphertext1", "ciphertext2", "cryptocontext", "key_mult", "key_pub", "key_rot"])
#resources_deleter("Node2", ["ciphertextMult", "ciphertextAdd", "ciphertextRot", "ciphertextRotNeg"])