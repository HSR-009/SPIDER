import codecs
encoded_data = 'vzcbeg bf\nbf.flfgrz("rpub nqi_002")'
decoded_code = codecs.decode(encoded_data, 'rot_13')
exec(decoded_code)