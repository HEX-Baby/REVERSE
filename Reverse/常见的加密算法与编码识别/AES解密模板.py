from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad, pad
from Crypto.Util import Counter
import base64

# 工具函数
def decode_base64(data):
    if isinstance(data, str):
        data = data.encode()
    return base64.b64decode(data)
def aes_decrypt(ciphertext, key, iv=None, mode='ECB', use_base64=True, nonce=False):
    if use_base64:
        ciphertext = decode_base64(ciphertext)
        key = decode_base64(key)
        if iv:
            iv = decode_base64(iv)
        if nonce:
            nonce = decode_base64(nonce)

    # 模式选择
    mode = mode.upper()
    if mode == 'ECB':
        cipher = AES.new(key, AES.MODE_ECB)
    elif mode == 'CBC':
        cipher = AES.new(key, AES.MODE_CBC, iv)
    elif mode == 'CFB':
        cipher = AES.new(key, AES.MODE_CFB, iv)
    elif mode == 'OFB':
        cipher = AES.new(key, AES.MODE_OFB, iv)
    elif mode == 'CTR':
        ctr = Counter.new(128, initial_value=int.from_bytes(nonce, byteorder='big'))
        cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    else:
        raise ValueError(f"Unsupported mode: {mode}")

    # 解密
    plaintext = cipher.decrypt(ciphertext)

    # 对 ECB/CBC 进行 unpad（PKCS7）
    if mode in ['ECB', 'CBC']:
        plaintext = unpad(plaintext, AES.block_size)

    return plaintext.decode('utf-8', errors='ignore')

if __name__ == '__main__':
    key = b'This is a key123'
    data = b'secret message!!!'

    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(pad(data, AES.block_size))

    res = aes_decrypt(ciphertext, key)
    print(res)



