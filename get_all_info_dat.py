import hashlib
import base58
import os
import struct
import binascii
import bsddb3 as bsddb
from Crypto.Hash import RIPEMD160
import time

def print_warning():
    return ("********************************************************\n"
            "*                                        *\n"
            "* Acest script este privat. Strict interzis pentru public *\n"
            "********************************************************\n")

def to_hex(data):
    return data.hex()

def sha256(data):
    return hashlib.sha256(data).digest()

def double_sha256(data):
    return sha256(sha256(data))

def ripemd160(data):
    h = RIPEMD160.new()
    h.update(data)
    return h.digest()

def pubkey_to_pubaddress(pubkey):
    digest = sha256(pubkey)
    ripemd = ripemd160(digest)
    prefixed_ripemd = b'\x00' + ripemd
    checksum = sha256(sha256(prefixed_ripemd))[:4]
    address = prefixed_ripemd + checksum
    return base58.b58encode(address)

def read_encrypted_key(wallet_filename):
    output = ""
    with open(wallet_filename, "rb") as wallet_file:
        wallet_file.seek(12)
        if wallet_file.read(8) != b"\x62\x31\x05\x00\x09\x00\x00\x00":  # BDB magic, Btree v9
            output += "ERROR: file is not a Bitcoin Core wallet\n"
            return None, output

    db_env = bsddb.db.DBEnv()
    db_env.open(os.path.dirname(wallet_filename), bsddb.db.DB_CREATE | bsddb.db.DB_INIT_MPOOL)
    db = bsddb.db.DB(db_env)

    try:
        db.open(wallet_filename, "main", bsddb.db.DB_BTREE, bsddb.db.DB_RDONLY)
        mkey = db.get(b"\x04mkey\x01\x00\x00\x00")
    finally:
        db.close()
        db_env.close()

    if not mkey:
        raise ValueError("Encrypted master key not found in the Bitcoin Core wallet file")

    encrypted_master_key, salt, method, iter_count = struct.unpack_from("<49p9pII", mkey)

    if method != 0:
        output += f"Warning: unexpected Bitcoin Core key derivation method {method}\n"

    iv = binascii.hexlify(encrypted_master_key[16:32]).decode()
    ct = binascii.hexlify(encrypted_master_key[-16:]).decode()
    iterations = '{:x}'.format(iter_count).zfill(8)

    target_mkey = binascii.hexlify(encrypted_master_key).decode() + binascii.hexlify(salt).decode() + iterations
    mkey_encrypted = binascii.hexlify(encrypted_master_key).decode()

    output += (f"Mkey_encrypted: {mkey_encrypted}\n"
               f"Target mkey  : {target_mkey}\n"
               f"CT           : {ct}\n"
               f"Salt         : {binascii.hexlify(salt).decode()}\n"
               f"IV           : {iv}\n"
               f"Raw Iter     : {iterations}\n"
               f"Iterations   : {str(int(iterations, 16))}\n")
    return target_mkey, output

def read_wallet(file_path, addresses):
    output = print_warning()

    mkey_info, mkey_output = read_encrypted_key(file_path)
    output += mkey_output

    with open(file_path, 'rb') as wallet:
        data = wallet.read()

    mkey_offset = data.find(b'mkey')
    if mkey_offset == -1:
        output += "There is no Master Key in the file\n"
        return output

    mkey_data = data[mkey_offset - 72:mkey_offset - 72 + 48]
    output += f"Mkey_encrypted: {to_hex(mkey_data)}\n"

    offset = 0

    while True:
        ckey_offset = data.find(b'ckey', offset)
        if ckey_offset == -1:
            break

        ckey_data = data[ckey_offset - 52:ckey_offset - 52 + 123]
        ckey_encrypted = ckey_data[:48]
        public_key_length = ckey_data[56]
        public_key = ckey_data[57:57 + public_key_length]

        addresses.append(f"Encrypted ckey: {to_hex(ckey_encrypted)}\nPublic key    : {to_hex(public_key)}\nPublic address: {pubkey_to_pubaddress(public_key)}\n")

        output += (f"Encrypted ckey: {to_hex(ckey_encrypted)}\n"
                   f"Public key    : {to_hex(public_key)}\n"
                   f"Public address: {pubkey_to_pubaddress(public_key)}\n")

        offset = ckey_offset + 1
    
    return output

def wallet_key_stats(wallet_filename):
    db_env = bsddb.db.DBEnv()
    db_env.open(os.path.dirname(wallet_filename), bsddb.db.DB_CREATE | bsddb.db.DB_INIT_MPOOL)
    db = bsddb.db.DB(db_env)
    output = ""

    try:
        db.open(wallet_filename, "main", bsddb.db.DB_BTREE, bsddb.db.DB_RDONLY)
        cursor = db.cursor()
        counts = {}
        avg_txn_size = 0
        meta = {}

        def is_zec_prefix(prefix):
            return prefix in ['t1', 't3']

        def is_kmd_prefix(prefix):
            return prefix in ['R', 'b']

        def detect_coin(counts, meta):
            coin = "BTC"
            prefix = meta.get('prefix', '')

            if is_kmd_prefix(prefix[0:1]):
                coin = "KMD or asset chain"
            elif is_zec_prefix(prefix):
                coin = "ZEC/HUSH"

            if 'sapzkey' in counts or 'sapzkeymeta' in counts:
                coin += " Sapling"
            elif 'zkey' in counts or 'zkeymeta' in counts:
                coin += " Sprout"

            return coin

        while True:
            item = cursor.next()
            if item is None:
                break
            k, v = item
            len_key = k[0]
            type_key = k[1:1+len_key]
            key = k[1+len_key:]
            klen = len(key)
            vlen = len(v)

            counts[type_key] = counts.get(type_key, 0) + 1
            if type_key == b'tx':
                avg_txn_size += vlen
            elif type_key == b'purpose':
                addr = k[2+len_key:]
                meta['prefix'] = addr[:2].decode()

        cursor.close()
        db.close()
        db_env.close()

        avg_txn_size = counts.get(b'tx', 0) and avg_txn_size / counts[b'tx']
        output += "\n===== Wallet Key Stats =====\n"
        for key_type, count in sorted(counts.items(), key=lambda item: item[1], reverse=True):
            output += f"{key_type.decode():<25} {count}\n"

        output += f"Total: {sum(counts.values())} keys in {len(counts)} key types\n"
        coin = detect_coin(counts, meta)
        output += f"Coin detection: {coin}\n"

    except Exception as e:
        output += f"Error reading wallet: {e}\n"
    finally:
        db.close()
        db_env.close()

    return output

def salvage_wallet(wallet_filename, aggressive=False):
    db_env = bsddb.db.DBEnv()
    db_env.open(os.path.dirname(wallet_filename), bsddb.db.DB_CREATE | bsddb.db.DB_INIT_MPOOL)

    try:
        salvaged_data = []
        db = bsddb.db.DB(db_env)
        db.salvage(wallet_filename, callback=lambda d, f: salvaged_data.append(d), flags=bsddb.db.DB_SALVAGE | (bsddb.db.DB_AGGRESSIVE if aggressive else 0))
        return salvaged_data
    except Exception as e:
        print(f"Error salvaging wallet: {e}")
        return None
    finally:
        db_env.close()

def parse_wallet_dump(salvaged_data):
    result = {}
    header_end = False
    data_end = False

    for line in salvaged_data:
        line = line.decode('utf-8').strip()
        if not header_end:
            if line == "HEADER=END":
                header_end = True
            continue
        if not data_end:
            if line == "DATA=END":
                data_end = True
            continue

        if header_end and not data_end:
            key = salvaged_data.pop(0).decode('utf-8').strip()
            val = salvaged_data.pop(0).decode('utf-8').strip()
            key_bytes = binascii.unhexlify(key)
            val_bytes = binascii.unhexlify(val)
            result[key_bytes] = val_bytes

    return result

def create_new_wallet(key_val_dict, dest_wallet_filename):
    if os.path.exists(dest_wallet_filename):
        os.remove(dest_wallet_filename)

    db_env = bsddb.db.DBEnv()
    db_env.open(os.path.dirname(dest_wallet_filename), bsddb.db.DB_CREATE | bsddb.db.DB_INIT_MPOOL)

    try:
        db = bsddb.db.DB(db_env)
        db.open(dest_wallet_filename, "main", bsddb.db.DB_BTREE, bsddb.db.DB_CREATE)

        for key, val in key_val_dict.items():
            db.put(key, val)

        db.close()
    except Exception as e:
        print(f"Error creating new wallet: {e}")
    finally:
        db_env.close()

def recover_wallet(src_wallet_filename, dest_wallet_filename):
    print("Starting wallet recovery...")
    salvaged_data = salvage_wallet(src_wallet_filename, aggressive=True)
    if not salvaged_data:
        print("Failed to salvage wallet.")
        return

    key_val_dict = parse_wallet_dump(salvaged_data)
    create_new_wallet(key_val_dict, dest_wallet_filename)
    print("Wallet recovery complete.")

def open_wallet(path):
    db_env = bsddb.db.DBEnv()
    db_env.open(os.path.dirname(path), bsddb.db.DB_CREATE | bsddb.db.DB_INIT_MPOOL)
    db = bsddb.db.DB(db_env)

    try:
        db.open(path, "main", bsddb.db.DB_BTREE, bsddb.db.DB_RDONLY)
        return db, db_env
    except Exception as e:
        print(f"Error opening wallet: {e}")
        return None, None

def foreach_item(db, func, data):
    cursor = db.cursor()
    while True:
        item = cursor.next()
        if item is None:
            break
        key, value = item
        func(key, value, data)
    cursor.close()

def public_key_to_bc_address(key, length):
    digest1 = sha256(key[:length])
    digest2 = ripemd160(digest1)
    final = b'\x00' + digest2
    checksum = double_sha256(final)[:4]
    address = final + checksum
    return base58.b58encode(address)

def digest_to_bc_address(digest160):
    final = b'\x00' + digest160
    checksum = double_sha256(final)[:4]
    address = final + checksum
    return base58.b58encode(address)

def display_and_save(key, value, addresses):
    key_stream = key
    value_stream = value
    type_len = key_stream[0]
    key_stream = key_stream[1:]
    key_type = key_stream[:type_len].decode()
    key_stream = key_stream[type_len:]

    if key_type in ['key', 'ckey']:
        public_key_length = key_stream[0]
        key_stream = key_stream[1:]
        public_key = key_stream[:public_key_length]
        b58 = public_key_to_bc_address(public_key, public_key_length)
        addresses.append(f"Public Key: {to_hex(public_key)}, Address: {b58}")
        print(f"{key_type} {b58}")

def find_key(db, address):
    def search_key(key, value, data):
        key_stream = key
        value_stream = value
        type_len = key_stream[0]
        key_stream = key_stream[1:]
        key_type = key_stream[:type_len].decode()
        key_stream = key_stream[type_len:]

        if key_type == 'key':
            public_key_length = key_stream[0]
            key_stream = key_stream[1:]
            public_key = key_stream[:public_key_length]
            private_key_length = value_stream[0]
            value_stream = value_stream[1:]
            private_key = value_stream[:private_key_length]
            b58 = public_key_to_bc_address(public_key, public_key_length)
            if b58 == address:
                print(f"Private key for {address} found!")
                # Export the private key
                key_obj = ECC.import_key(private_key)
                print(key_obj.export_key(format='PEM'))
                return True
        return False

    foreach_item(db, search_key, address)

def display_all_and_save(db, addresses):
    foreach_item(db, display_and_save, addresses)

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <wallet.dat> <output.txt>")
        sys.exit(0)

    addresses = []
    output = read_wallet(sys.argv[1], addresses)
    output += wallet_key_stats(sys.argv[1])

    db, db_env = open_wallet(sys.argv[1])
    if db and db_env:
        display_all_and_save(db, addresses)
        db.close()
        db_env.close()

    with open(sys.argv[2], 'w') as file:
        file.write(output)
        for address in addresses:
            file.write(f"{address}\n")
