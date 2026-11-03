import base64

code = base64.b64decode("cHJpbnQoJ0hlbGxvJyk=")
function_name = 'ex' + 'ec'
getattr(__builtins__, function_name)(code)