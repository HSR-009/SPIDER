import base64

data = b"SPIDER project data"
encoded = base64.b64encode(data)

print(encoded)