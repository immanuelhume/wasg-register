# wasg-register : Registers for a new Wireless@SG SSA account
#
# Python equivalent of the Wireless@SG app available at:
#    https://www2.imda.gov.sg/programme-listing/wireless-at-sg/Wireless-at-SG-for-Consumers
#

import argparse
import codecs
import datetime
import sys

import requests
from Crypto.Cipher import AES
from loguru import logger

from .constants import DEFAULT_ISP, DEFAULT_TRANSID, ISP_CONFIG, RC_SUCCESS
from .exceptions import HTTPNotFoundExn, MalformedResponseExn, ServerErrorExn

VERBOSE = False


def _validate(resp, key, val=None, fatal=False):
    "Helper function to validate server responses."

    def handleErr(m):
        if not fatal:
            logger.warning(m)
        else:
            raise MalformedResponseExn(m)

    if key not in resp:
        logger.error(f"Invalid server response: {repr(resp)}")
        handleErr(f"Server response did not contain key '{key}'")
    elif val is not None and resp[key] != val:
        logger.error(f"Invalid server response: {repr(resp)}")
        handleErr(
            f"Unexpected server response, key '{key}' is '{resp[key]}', not '{val}'."
        )


def _check_for_error(resp):
    "Checks if the response is an error message. If so, print it out and bail."

    _validate(resp, "status", fatal=True)
    _validate(resp["status"], "resultcode", fatal=True)
    rc = int(resp["status"]["resultcode"])

    if rc != RC_SUCCESS:
        logger.error(f"Server response reports an error with resultcode {rc}")
        _validate(resp, "body", fatal=True)

        msg = resp["body"]["message"] if "message" in resp["body"] else "(empty)"
        logger.error(f"Received error message from server: {msg}")
        raise ServerErrorExn(msg)


def request_registration(
    isp,
    salutation,
    name,
    gender,
    dob,
    mobile,
    country,
    email,
    transid,
    retrieve_mode=False,
):
    logger.info("Preparing registration request...")

    if retrieve_mode:
        api = "retrieve_user_r11x2a"
        api_version = ISP_CONFIG[isp]["retrieve_api_versions"][0]
    else:
        api = "create_user_r11x1a"
        api_version = ISP_CONFIG[isp]["create_api_versions"][0]

    r = requests.get(
        ISP_CONFIG[isp]["essa_url"],
        params={
            "api": api,
            "salutation": salutation,
            "name": name,
            "gender": gender,
            "dob": dob,
            "mobile": mobile,
            "nationality": country,
            "email": email,
            "tid": transid,
        },
    )

    if r.status_code != requests.codes.ok:
        raise HTTPNotFoundExn("Failed to make request query.")

    try:
        logger.info("Attempting to parse response as JSON...")
        resp = r.json()
    except ValueError:
        raise MalformedResponseExn("Could not parse JSON.")

    _check_for_error(resp)
    _validate(resp, "api", api)
    _validate(resp, "version", api_version)

    _validate(resp, "body", fatal=True)
    _validate(resp["body"], "success_code", fatal=True)

    return resp["body"]["success_code"]


def validate_otp(isp, dob, mobile, otp, success_code, transid, retrieve_mode=False):
    logger.info("Validating OTP...")

    if retrieve_mode:
        api = "retrieve_user_r11x2b"
        api_version = ISP_CONFIG[isp]["retrieve_api_versions"][1]
    else:
        api = "create_user_r11x1b"
        api_version = ISP_CONFIG[isp]["create_api_versions"][1]

    r = requests.get(
        ISP_CONFIG[isp]["essa_url"],
        params={
            "api": api,
            "dob": dob,
            "mobile": mobile,
            "otp": otp,
            "success_code": success_code,
            "tid": transid,
        },
    )

    if r.status_code != requests.codes.ok:
        raise HTTPNotFoundExn("Failed to make validation query.")

    try:
        logger.info("Attempting to parse response as JSON...")
        resp = r.json()
    except ValueError:
        raise MalformedResponseExn("Malformed response from server.")

    _check_for_error(resp)
    _validate(resp, "api", api)
    _validate(resp, "version", api_version)
    _validate(resp, "body", fatal=True)
    _validate(resp["body"], "userid", fatal=True)
    _validate(resp["body"], "enc_userid", fatal=True)
    _validate(resp["body"], "tag_userid", fatal=True)
    _validate(resp["body"], "enc_password", fatal=True)
    _validate(resp["body"], "tag_password", fatal=True)
    _validate(resp["body"], "iv", fatal=True)

    def hexdecode(s):
        return codecs.decode(bytes(s, "utf8"), encoding="hex")

    return {
        "userid": bytes(resp["body"]["userid"], "utf8"),
        "enc_userid": hexdecode(resp["body"]["enc_userid"]),
        "tag_userid": hexdecode(resp["body"]["tag_userid"]),
        "enc_password": hexdecode(resp["body"]["enc_password"]),
        "tag_password": hexdecode(resp["body"]["tag_password"]),
        "nonce": bytes(resp["body"]["iv"], "utf8"),
    }


def build_decrypt_key(date, transid, otp):
    date_hex = b"%03x" % int(date.strftime("%e%m").strip())
    otp_hex = b"%05x" % int(otp)
    key_hex = date_hex + transid + otp_hex
    return codecs.decode(key_hex, "hex")


def decrypt(key, nonce, tag, ciphertext):
    aes = AES.new(key, AES.MODE_CCM, nonce)
    aes.update(tag)
    return aes.decrypt(ciphertext)


def errquit(m):
    logger.error(m)
    return 1


def parseArgs():
    parser = argparse.ArgumentParser(
        description="Wireless@SG registration utility.",
    )

    parser.add_argument("mobile", type=str, help="Mobile phone number")
    parser.add_argument("dob", type=str, help="Date of birth in DDMMYYYY format")

    parser.add_argument(
        "-I",
        "--isp",
        type=str,
        choices=ISP_CONFIG.keys(),
        default=DEFAULT_ISP,
        help="ISP to register with",
    )

    parser.add_argument("-s", "--salutation", type=str, default="Dr", help="Salutation")

    parser.add_argument(
        "-n", "--name", type=str, default="Some Person", help="Full name"
    )

    parser.add_argument("-g", "--gender", type=str, default="f", help="Gender")

    parser.add_argument(
        "-c", "--country", type=str, default="SG", help="Nationality country code"
    )

    parser.add_argument(
        "-e",
        "--email",
        type=str,
        default="nonexistent@noaddresshere.com",
        help="Email address",
    )

    parser.add_argument(
        "-t", "--transid", type=bytes, default=DEFAULT_TRANSID, help="Transaction ID"
    )

    parser.add_argument(
        "-1",
        "--registration-phase-only",
        action="store_true",
        help="Terminate after registration phase, returns success code.",
    )

    parser.add_argument(
        "-O",
        "--otp",
        type=str,
        help=(
            "OTP received on mobile. Note that if this is set, then wasg-register will skip the registration phase",
            "and move immediately to OTP validation. Success-code must also be provided.",
        ),
    )

    parser.add_argument(
        "-S",
        "--success-code",
        type=str,
        help=(
            "Success code received during registration phase. Note that if this is set, then wasg-register",
            "will skip the registration phase and move immediately to OTP validation. OTP must also be provided.",
        ),
    )

    parser.add_argument(
        "-D",
        "--decryption-date",
        type=str,
        help="Date the OTP was generated, for use in decryption, in YYMMDD format.",
    )

    parser.add_argument(
        "-r",
        "--retrieve-mode",
        action="store_true",
        help="Run in retrieve mode, for existing accounts.",
    )

    args = parser.parse_args()

    return args


def register(args):
    otp = None
    success_code = None

    if args.otp is None and args.success_code is None:
        # Begin registration phase.

        success_code = request_registration(
            args.isp,
            args.salutation,
            args.name,
            args.gender,
            args.dob,
            args.mobile,
            args.country,
            args.email,
            args.transid,
            retrieve_mode=args.retrieve_mode,
        )
        logger.info(f"Got success code: {success_code}")

        if args.registration_phase_only:
            print("Success code: %s" % success_code)
            return 0

        print("OTP will be sent to mobile phone number %s" % args.mobile)
        otp = input("Enter OTP to continue: ")

    else:
        # Skipping registration phase, make sure we have OTP and success code.
        if args.otp is None or args.success_code is None:
            return errquit(
                "Both success code and OTP must be provided to skip registration phase."
            )

        success_code = args.success_code
        otp = args.otp

    r = validate_otp(
        args.isp,
        args.dob,
        args.mobile,
        otp,
        success_code,
        args.transid,
        retrieve_mode=args.retrieve_mode,
    )

    if args.decryption_date is not None:
        decryption_date = datetime.datetime.strptime(args.decryption_date, "%Y%m%d")
    else:
        decryption_date = datetime.datetime.now()

    try_dates = (
        decryption_date,
        decryption_date + datetime.timedelta(1),
        decryption_date + datetime.timedelta(-1),
    )

    found = False
    for date in try_dates:
        key = build_decrypt_key(date, args.transid, otp)
        if decrypt(key, r["nonce"], r["tag_userid"], r["enc_userid"]) == r["userid"]:
            logger.info(f"Successfully decrypted using date {date.strftime('%Y%m%d')}")
            found = True
            break

    if not found:
        return errquit("Decryption failed. Try a different date?")

    logger.info(f"Decryption key: {codecs.encode(key, 'hex')}")
    logger.info(f"Nonce: {r['nonce']}")
    logger.info(f'userid tag: {codecs.encode(r["tag_userid"], "hex")}')
    logger.info(f'password tag: {codecs.encode(r["tag_password"], "hex")}')

    password = decrypt(key, r["nonce"], r["tag_password"], r["enc_password"])

    print("Credentials:")
    print("\tuserid = %s" % r["userid"].decode())
    print("\tpassword = %s" % password.decode())
    print(
        """

    Please connect to the Wireless@SGx using these settings:
    - WPA2 Enterprise
    - PEAP
    - MSCHAPv2
    """
    )

    return 0


def main():
    try:
        args = parseArgs()
        sys.exit(register(args))
    except HTTPNotFoundExn as e:
        logger.error(f"HTTP error: {e}")
        sys.exit(1)
    except MalformedResponseExn as e:
        logger.error(f"Malformed response from server: {e}")
        sys.exit(1)
    except ServerErrorExn as e:
        logger.error(f"Server responded with error message: {e}")
        sys.exit(1)
