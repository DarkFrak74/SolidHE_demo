import requests

server_url = "http://localhost:3000"
pod_name = "SolidHE-pod"

base_url = f"{server_url}/{pod_name}"


# Node_name identify both the local subfolder and the pod subfolder where the data are going to be stored
def write_data(node_name, file_name):
    resource_location = f"{node_name}/{file_name}"
    url = f"{base_url}/{resource_location}"

    # Stream of local file (instead of reading the whole file)
    with open(resource_location, "rb") as file:
        response = requests.put(url, data=file, headers={'Content-Type': 'application/binary'})

    return response.status_code


def read_data(node_name, file_name):
    resource_location = f"{node_name}/{file_name}"
    url = f"{base_url}/{resource_location}"

    # Get the response as a stream
    with requests.get(url, stream=True) as response:
        response.raise_for_status()
        # Write the response to local fine in chunks
        with open(resource_location, "wb") as file:
            for chunk in response.iter_content(chunk_size=8192):
                file.write(chunk)

        return response.status_code
