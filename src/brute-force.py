import os
import hashlib
import logging
import argparse
import matplotlib.pyplot as plt
from PIL import Image, ImageFile


def main(args) -> None:
    with open(args.hashed_headers, "r") as file:
        header_hashes = file.readlines()

    if len(header_hashes) != len(os.listdir(args.input_images)):
        logging.error("The number of hashed headers must match the number of PPM images!")
        exit(1)

    header_hashes = set(bytes.fromhex(header_hash) for header_hash in header_hashes)
    logging.info("Loaded hashed headers.")

    file_sizes = [os.path.getsize(os.path.abspath(f"{args.input_images}/{filename}")) for filename in os.listdir(args.input_images)]
    # each component of the RGB values is stored in a single byte => 3B/pixel;
    # get the square root of the largest image, in pixels;
    # double that, to make sure rectangular images which are longer in width are covered;
    brute_force_upper_bound = int((max(file_sizes) / 3) ** 0.5 * 2)

    logging.info("Initiating image dimension brute force attack.")
    brute_forced_hashes = {}
    for i in range(brute_force_upper_bound):
        for j in range(brute_force_upper_bound):
            potential_header = bytes(f"P6 {i} {j} 255", "utf-8")

            hasher = hashlib.sha256()
            hasher.update(potential_header)
            hash_of_potential_header = hasher.digest()

            if hash_of_potential_header in header_hashes:
                brute_forced_hashes[hash_of_potential_header] = ((i, j), potential_header)
                logging.info(f"Found dimension pair {len(brute_forced_hashes)}/{len(header_hashes)}.")

                # all dimension pairs were found
                if len(brute_forced_hashes) == len(header_hashes):
                    break
        # continue iterating, for the remaining hashed headers
        else:
            continue

        # the 'break' in the inner loop was reached, which means that the outer loop must also halt
        break

    if not brute_forced_hashes:
        logging.error("Brute force failed (no dimension pairs could be found).")
        exit(1)

    logging.info("Interactive mode initiated. For each input image, you will be asked to enter 'y' when a legible representation appears, and 'n' otherwise.")
    for filename in os.listdir(args.input_images):
        with open(f"{args.input_images}/{filename}", "rb") as file:
            encrypted_file = file.read()
        logging.info(f"Loaded '{filename}'.")

        for header_hash in header_hashes:
            extended_filename = f"{args.output_images}/{filename}.{brute_forced_hashes[header_hash][0][0]}x{brute_forced_hashes[header_hash][0][1]}.{header_hash[:3].hex()}"
            with open(extended_filename, "wb") as file:
                # there must be a whitespace character between the header and the image itself
                file.write(brute_forced_hashes[header_hash][1] + b" " + encrypted_file)

            encrypted_image = Image.open(extended_filename)
            plt.imshow(encrypted_image)
            plt.show()

            if input("Was that legible? [y/N] ") == "y":
                # we can assume that each dimension pair is unique, and is therefore associated with a single image
                header_hashes.discard(header_hash)
                break
            else:
                # illegible images mustn't be saved
                os.remove(extended_filename)

    logging.info("Brute force completed.")


if __name__ == '__main__':
    # force Pillow to load smaller than expected images in regard to the size specified in their headers
    ImageFile.LOAD_TRUNCATED_IMAGES = True
    logging.basicConfig(format="%(levelname)s: %(message)s", level=logging.INFO)

    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input-images", required=True, type=str, dest="input_images", metavar="INPUT-IMAGES", help="directory containing header-less raw PPM images, encrypted using the ECB mode")
    parser.add_argument("-hh", "--hashed-headers", required=True, type=str, dest="hashed_headers", metavar="HASHED-HEADERS",help="file containing the hashes of the headers associated with the PPM images, each one on a separate line")
    parser.add_argument("-o", "--output-images", required=True, type=str, dest="output_images", metavar="OUTPUT-IMAGES", help="directory in which to store the brute-forced PPM images")

    arguments = parser.parse_args()
    main(arguments)
