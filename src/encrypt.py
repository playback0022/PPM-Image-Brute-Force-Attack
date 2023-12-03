import os
import hashlib
import secrets
import argparse
import logging
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


def is_valid_header(header: [bytes]) -> bool:
    """
        Convenience function which takes a list of 4 bytes objects and
    checks whether they constitute a valid raw PPM image header
    """
    if len(header) != 4:
        return False

    header = [binary_component.decode("utf-8") for binary_component in header]

    if header[0] != "P6":
        return False

    if not header[1].isdecimal() or not header[2].isdecimal():
        return False

    if header[3] != "255":
        return False

    return True


def main(args) -> None:
    if not os.path.isdir(args.input_images) or not os.path.isdir(args.output_images):
        logging.error(f"One or both of the provided directories are invalid!")
        exit(1)

    encryption_key = secrets.token_bytes(32)
    with open(f"{args.output_images}/encryption-key", "wb") as file:
        file.write(encryption_key)
    logging.info(f"Encryption key generated at '{args.output_images}/encryption-key'.")

    for filename in os.listdir(args.input_images):
        with open(f"{args.input_images}/{filename}", "rb") as file:
            # for valid PPM images, this will yield a list with 5 elements,
            # the first 4 of which make up the header, while the last is the
            # image data itself
            unencrypted_image = file.read().split(maxsplit=4)

        if not is_valid_header(unencrypted_image[:4]):
            logging.warning(f"Skipped invalid file '{filename}'.")
            continue

        # convert the header to a string, in order to add spaces, and then back to a bytes object
        header = " ".join([binary_component.decode("utf-8") for binary_component in unencrypted_image[:4]])
        header = header.encode("utf-8")
        hasher = hashlib.sha256()
        hasher.update(header)

        with open(f"{args.output_images}/{filename}.header.sha256", "w") as file:
            file.write(hasher.digest().hex())
        logging.info(f"Processed header of '{filename}'.")

        cipher = AES.new(encryption_key, AES.MODE_ECB)
        encrypted_image = cipher.encrypt(pad(unencrypted_image[4], 16))
        with open(f"{args.output_images}/{filename}.encrypted", "wb") as file:
            file.write(encrypted_image)
        logging.info(f"Encrypted image '{filename}'.")

    logging.info("Finished batch job.")


# the problem with this security strategy is the receiver has no way of retrieving the header data, other than
# brute-force, even when the hashes are transmitted in order, because the sha256 hash function is irreversible
if __name__ == '__main__':
    logging.basicConfig(format="%(levelname)s: %(message)s", level=logging.INFO)

    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input-images", required=True, type=str, dest="input_images", metavar="INPUT-IMAGES",
                        help="directory containing the unencrypted raw PPM images")
    parser.add_argument("-o", "--output-images", required=True, type=str, dest="output_images", metavar="OUTPUT-IMAGES",
                        help="directory in which the header-less encrypted PPM images will be stored, along with their header hashes")

    arguments = parser.parse_args()
    main(arguments)
