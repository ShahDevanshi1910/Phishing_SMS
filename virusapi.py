import requests
# Define your API key
api_key = 'c2ad5bb192d4f6ad664c6bf363ef5db75d76d81856d9868a0b18f8ce7196cfd5'

# Define the URL for the API endpoint
url = 'https://www.virustotal.com/api/v3/urls'

# Define the headers with your API key
headers = {
    'x-apikey': api_key
}

# Define the parameters for the request
params = {
    'url': 'https://localhost:3000'
}

# Make the API request
response = requests.get(url, headers=headers, params=params)

# Check if the request was successful (status code 200)
if response.status_code == 200:
    # Print the response content
    print(response.json())
else:
    # Print an error message if the request was not successful
    print(f'Error: {response.status_code}')
