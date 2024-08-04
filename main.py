import binascii, hashlib, hmac, struct
from web3 import Web3
from ecdsa.curves import SECP256k1
from datetime import datetime
from eth_utils import to_checksum_address, keccak as eth_utils_keccak
import time
from os import path

BIP39_PBKDF2_ROUNDS = 2048
BIP39_SALT_MODIFIER = "mnemonic"
BIP32_PRIVDEV = 0x80000000
BIP32_CURVE = SECP256k1
BIP32_SEED_MODIFIER = b'Bitcoin seed'
ETH_DERIVATION_PATH = "m/44'/60'/0'/0"

# Define ACCESS API
infura_url = "https://mainnet.infura.io/v3/30320110ad274ecb9c6f0dd1f18d3136"
web3 = Web3(Web3.HTTPProvider(infura_url))
web3.eth.account.enable_unaudited_hdwallet_features()
print(web3.is_connected())
print(web3.eth.block_number)

class PublicKey:
    def __init__(self, private_key):
        self.point = int.from_bytes(private_key, byteorder='big') * BIP32_CURVE.generator

    def __bytes__(self):
        xstr = self.point.x().to_bytes(32, byteorder='big')
        parity = self.point.y() & 1
        return (2 + parity).to_bytes(1, byteorder='big') + xstr

    def address(self):
        x = self.point.x()
        y = self.point.y()
        s = x.to_bytes(32, 'big') + y.to_bytes(32, 'big')
        return to_checksum_address(eth_utils_keccak(s)[12:])

def mnemonic_to_bip39seed(mnemonic, passphrase):
    mnemonic = bytes(mnemonic, 'utf8')
    salt = bytes(BIP39_SALT_MODIFIER + passphrase, 'utf8')
    return hashlib.pbkdf2_hmac('sha512', mnemonic, salt, BIP39_PBKDF2_ROUNDS)

def bip39seed_to_bip32masternode(seed):
    k = seed
    h = hmac.new(BIP32_SEED_MODIFIER, seed, hashlib.sha512).digest()
    key, chain_code = h[:32], h[32:]
    return key, chain_code

def derive_bip32childkey(parent_key, parent_chain_code, i):
    assert len(parent_key) == 32
    assert len(parent_chain_code) == 32
    k = parent_chain_code
    if (i & BIP32_PRIVDEV) != 0:
        key = b'\x00' + parent_key
    else:
        key = bytes(PublicKey(parent_key))
    d = key + struct.pack('>L', i)
    while True:
        h = hmac.new(k, d, hashlib.sha512).digest()
        key, chain_code = h[:32], h[32:]
        a = int.from_bytes(key, byteorder='big')
        b = int.from_bytes(parent_key, byteorder='big')
        key = (a + b) % BIP32_CURVE.order
        if a < BIP32_CURVE.order and key != 0:
            key = key.to_bytes(32, byteorder='big')
            break
        d = b'\x01' + h[32:] + struct.pack('>L', i)
    return key, chain_code

def parse_derivation_path(str_derivation_path):
    path = []
    if str_derivation_path[0:2] != 'm/':
        raise ValueError("Can't recognize derivation path. It should look like \"m/44'/60/0'/0\".")
    for i in str_derivation_path.lstrip('m/').split('/'):
        if "'" in i:
            path.append(BIP32_PRIVDEV + int(i[:-1]))
        else:
            path.append(int(i))
    return path

def mnemonic_to_private_key(mnemonic, str_derivation_path, passphrase=""):
    derivation_path = parse_derivation_path(str_derivation_path)
    bip39seed = mnemonic_to_bip39seed(mnemonic, passphrase)
    master_private_key, master_chain_code = bip39seed_to_bip32masternode(bip39seed)
    private_key, chain_code = master_private_key, master_chain_code
    for i in derivation_path:
        private_key, chain_code = derive_bip32childkey(private_key, chain_code, i)
    return private_key

def balance_change_log(private_key, before, after):
    log_path = f'log/{binascii.hexlify(private_key).decode("utf-8")}'
    if not path.exists(log_path):
        tmp = open(log_path, "w+")
        tmp.close()

    with open(log_path, "a") as myfile:
        now = datetime.now()
        myfile.write(f'{now.strftime("%Y-%m-%d %H:%M:%S")}: {before} => {after}')
        myfile.close()


def check_balance(account, unit = "ether"):
    private_key = account.key
    public_key = PublicKey(private_key)

    # Fill in your account here
    balance = web3.eth.get_balance(public_key.address())
    # Format
    balance = web3.from_wei(balance, unit)

    balance_path = f'wallet/{binascii.hexlify(private_key).decode("utf-8")}'
    if not path.exists(balance_path):
        tmp = open(balance_path, "w+")
        tmp.write('0.0')
        tmp.close()

    file = open(balance_path, 'r+')
    prev_balance = file.readline()
    if prev_balance.isdigit():
        prev_balance = float(prev_balance)
    else:
        tmp = open(balance_path, "w+")
        tmp.write('0.0')
        tmp.close()
        prev_balance = 0.0

    if balance != prev_balance:
        print(f'balance changed: {prev_balance} => {balance}')
        balance_change_log(private_key, prev_balance, balance)
        tmp = open(balance_path, "w+")
        tmp.write(f'{balance}')
        tmp.close()

    print(f'balance info: {public_key.address()}', balance)


if __name__ == '__main__':
    # Input mnemonic for seed here.
    mnemonic = "wash bamboo tool memory pepper toddler kiss hero mail anger limit favorite"
    print('-------------------- MNEMONIC --------------------')
    print(mnemonic)

    # Infinite loop to continuously generate keys and check balances
    while True:
        for i in range(10):
            acc = web3.eth.account.from_mnemonic(mnemonic, account_path=f"m/44'/60'/0'/0/{i}")
            check_balance(acc)

        # Wait for some time before generating the next key
        time.sleep(10)  # Adjust the delay as needed
