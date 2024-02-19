def decode_utf8_2d_array(array_2d):
    decoded_array = list(
        map(lambda row: list(map(lambda elem: elem.decode("utf-8"), row)), array_2d)
    )
    return decoded_array
