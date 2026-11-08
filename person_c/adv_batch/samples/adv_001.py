import base64
encoded_data = 'aW1wb3J0IG9zCm9zLnN5c3RlbSgiZWNobyBhZHZfMDAxIik='
decoded_code = base64.b64decode(encoded_data)
exec(decoded_code)