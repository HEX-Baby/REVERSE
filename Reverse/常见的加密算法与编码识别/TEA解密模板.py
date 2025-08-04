def tea_decode(cipher, key, delta):
    v0, v1 = cipher
    k0, k1, k2, k3 = key
    sum = (delta * 32) & 0xFFFFFFFF

    for i in range(32):
        v1 = (v1 - (((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3))) & 0xFFFFFFFF
        v0 = (v0 - (((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1))) & 0xFFFFFFFF
        sum = (sum - delta) & 0xFFFFFFFF

    return v0, v1

