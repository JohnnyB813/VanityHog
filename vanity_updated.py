from ecdsa import SigningKey, SECP256k1
from Crypto.Hash import RIPEMD160, SHA256
import multiprocessing
import argparse
import time


##############################
# Functions
##############################
def generate_address(prefix, counter=0):
    # Predefined hash objects
    sha_hasher = SHA256.new()
    ripemd_hasher = RIPEMD160.new()

    while True:
        # Counter
        counter += 1
        # generate private key
        pk = SigningKey.generate(curve=SECP256k1)

        # derive public key
        pubkey = pk.get_verifying_key().to_string('compressed')

        # Reset hashers and update
        sha_hasher.update(pubkey)
        ripemd_hasher.update(sha_hasher.digest())
        addr_raw = ripemd_hasher.digest()

        # generate address by appending checksum
        if addr_raw.hex().startswith(prefix):
            addr_hash = SHA256.SHA256Hash(addr_raw).digest()
            checksum = addr_hash[0:4]
            addr = addr_raw + checksum
            return pk, pubkey, addr, counter


def main():
    parser = argparse.ArgumentParser(description='Generate Bitcoin addresses until a specified prefix is matched')
    parser.add_argument('--prefix', type=str, help='Desired prefix for the Bitcoin address')
    args = parser.parse_args()
    start_time = time.time()

    if not args.prefix:
        print("Please provide a prefix using --prefix=")
        return

    # Number of processes to run concurrently
    num_processes = multiprocessing.cpu_count()
    with multiprocessing.Pool(processes=num_processes) as pool:
        result = next(pool.imap_unordered(generate_address, [args.prefix] * num_processes), None)

    if result:
        private_key, public_key, address, counter = result
        print("Private Key:", private_key.to_string().hex())
        print("Public Key:", public_key.hex())
        print("Address:", address.hex())
        print("Checks:", counter * multiprocessing.cpu_count(), "in", round(time.time() - start_time), "seconds")
    else:
        print("No address with prefix", args.prefix, "found.")


if __name__ == "__main__":
    main()