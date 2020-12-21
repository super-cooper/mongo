#! /usr/bin/env python3
"""Mock GCP KMS Endpoint."""
import argparse
import logging
import sys

import kms_http_common

SUPPORTED_FAULT_TYPES = [
    kms_http_common.FAULT_ENCRYPT,
    kms_http_common.FAULT_ENCRYPT_CORRECT_FORMAT,
    kms_http_common.FAULT_DECRYPT,
    kms_http_common.FAULT_DECRYPT_CORRECT_FORMAT,
    kms_http_common.FAULT_DECRYPT_WRONG_KEY,
]


class GcpKmsHandler(kms_http_common.KmsHandlerBase):
    """
    Handle requests from GCP KMS Monitoring and test commands
    """

    def _validate_signature(self, headers, raw_input):
        pass

    def _do_operation(self, raw_input):
        print("FALALALALALALALA")
        print("DO OP")
        print(raw_input)
        print(self.headers)

    def _do_encrypt(self, raw_input):
        print("FALALALALALALALA")
        print("DO ENCRYPT")
        print(raw_input)
        print(self.headers)

    def _do_encrypt_faults(self, raw_ciphertext):
        print("FALALALALALALALA")
        print("DO ENCRYPT FAULTS")
        print(raw_ciphertext)
        print(self.headers)

    def _do_decrypt(self, raw_input):
        print("FALALALALALALALA")
        print("DO DECRYPT")
        print(raw_input)
        print(self.headers)

    def _do_decrypt_faults(self, blob):
        print("FALALALALALALALA")
        print("DO DECRYPT FAULTS")
        print(blob)
        print(self.headers)


def main():
    """Main Method."""
    parser = argparse.ArgumentParser(description='MongoDB Mock AWS KMS Endpoint.')

    parser.add_argument('-p', '--port', type=int, default=8000, help="Port to listen on")

    parser.add_argument('-v', '--verbose', action='count', help="Enable verbose tracing")

    parser.add_argument('--fault', type=str, help="Type of fault to inject")

    parser.add_argument('--disable-faults', action='store_true', help="Disable faults on startup")

    parser.add_argument('--ca_file', type=str, required=True, help="TLS CA PEM file")

    parser.add_argument('--cert_file', type=str, required=True, help="TLS Server PEM file")

    args = parser.parse_args()
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)

    if args.fault:
        if args.fault not in SUPPORTED_FAULT_TYPES:
            print("Unsupported fault type %s, supports types are %s" % (args.fault, SUPPORTED_FAULT_TYPES))
            sys.exit(1)

        kms_http_common.fault_type = args.fault

    if args.disable_faults:
        kms_http_common.disable_faults = True

    kms_http_common.run(args.port, args.cert_file, args.ca_file, GcpKmsHandler)


if __name__ == '__main__':
    main()
