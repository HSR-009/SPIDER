import base64
encoded_data = 'aW1wb3J0IG9zCgpvcy5zeXN0ZW0oIndob2FtaSIp'
decoded_code = base64.b64decode(encoded_data)
exec(decoded_code)