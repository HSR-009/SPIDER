counter = 0
counter += 1
if counter >= 3:
    import base64
    
    code = base64.b64decode("cHJpbnQoJ0hlbGxvJyk=")
    exec(code)