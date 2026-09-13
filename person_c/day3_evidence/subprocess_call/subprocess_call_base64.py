import base64
encoded_data = 'aW1wb3J0IHN1YnByb2Nlc3MKCnN1YnByb2Nlc3MucnVuKFsid2hvYW1pIl0p'
decoded_code = base64.b64decode(encoded_data)
exec(decoded_code)