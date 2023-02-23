#
# Copyright 2022 NXP
# SPDX-License-Identifier: Apache-2.0
#
import logging
import os
import subprocess
import sys
import traceback

logging.basicConfig(format='%(message)s', level=logging.DEBUG)
log = logging.getLogger(__name__)

if sys.platform.startswith('win'):
    cur_dir=os.path.abspath(os.path.dirname(__file__))
    library_name="sssProvider.dll"
    provider_path=os.path.join(cur_dir,'..','bin')
    provider=os.path.join(cur_dir,'..','bin',library_name)
    openssl_bin= os.path.join(cur_dir, '..', '..', '..', '..', 'ext', 'openssl-30', 'bin', 'openssl.exe')
else:
    cur_dir = os.path.abspath(os.path.dirname(__file__))
    library_name="libsssProvider.so"
    provider_path=os.path.join(cur_dir,'..','bin')
    provider=os.path.join(cur_dir,'..','bin',library_name)
    if "OPENSSL30_BINARY" in os.environ:
        openssl_bin = os.environ["OPENSSL30_BINARY"]
        print("\n Using OpenSSL from %s \n" %(openssl_bin))
    else:
        print("\n *** Using Installed OpenSSL ***")
        print(" *** NOTE: If OpenSSL 3.0 is installed in different location, set OPENSSL30_BINARY environment variable ***")
        print(" *** export OPENSSL30_BINARY=<OPENSSL 3.0 exe> \n")
        openssl_bin="openssl"

SUPPORTED_EC_KEY_TYPES = [
    "prime192v1",
    "secp224r1",
    "prime256v1",
    "secp384r1",
    "secp521r1",
    "secp160k1",
    "secp192k1",
    "secp224k1",
    "secp256k1",
    "brainpoolP160r1",
    "brainpoolP192r1",
    "brainpoolP224r1",
    "brainpoolP256r1",
    "brainpoolP320r1",
    "brainpoolP384r1",
#    "brainpoolP512r1",
]
SUPPORTED_CONNECTION_TYPES = [
    "t1oi2c",
    "vcom",
    "jrcpv1",
    "jrcpv2",
]
SUPPORTED_RSA_KEY_TYPES = [
    "rsa1024",
    "rsa2048",
    "rsa3072",
    "rsa4096"
]


def run(cmd_str, ignore_result=0, exp_retcode=0):
    log.info("Running command:")
    log.info("%s" % (cmd_str,))
    pipes = subprocess.Popen(
        cmd_str,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=True,
    )
    std_out, std_err = pipes.communicate()
    std_out = std_out.strip()
    std_err = std_err.strip()
    log.info("%s" % std_out.decode())
    if not ignore_result:
        if pipes.returncode != exp_retcode:
            log.error("ERROR: Return code: %s, Expected return code: %s " % (pipes.returncode, exp_retcode))
            log.error("ERROR: std_err: %s" % std_err.decode())
        else:
            log.info("Command execution was successful.")
        assert pipes.returncode == exp_retcode


def session_open(subsystem, connection_data, connection_type, auth_type, auth_key):
    ''' Open session based on IOT Secure Element selected. '''
    import sss.const as const
    import sss.connect as connect
    import sss.session as session

    log.info("###############################################################")
    log.info("#")
    log.info("#     SUBSYSTEM            : %s" % subsystem)
    log.info("#     CONNECTION_TYPE      : %s" % connection_type)
    log.info("#     CONNECTION_PARAMETER : %s" % connection_data)
    log.info("#")
    log.info("###############################################################")

    connect.do_open_session(const.SUBSYSTEM_TYPE[subsystem],
                          const.CONNECTION_TYPE[connection_type], connection_data,
                          auth_type=const.AUTH_TYPE_MAP[auth_type][0],
                          scpkey=auth_key)

    session_obj = session.Session()
    try:
        session_obj.session_open()
    except Exception as exc:
        error_log_file = os.path.abspath(os.path.dirname(__file__)) + os.sep + "error_log.txt"
        if not os.path.isfile(error_log_file):
            err_write = open(error_log_file, 'w+')
        else:
            err_write = open(error_log_file, 'a+')
        traceback.print_exc(None, err_write)
        err_write.close()
        return None
    return session_obj
def session_close(session):
    ''' Close opened session. '''
    import sss.connect as connect
    import sss.util as util

    if session:
        session.session_close()

    if os.path.isfile(util.get_session_pkl_path()):
        connect.do_close_session()
def compare(input_file, decrypt_file):
    with open(input_file, 'rb') as raw_data:
        in_data = raw_data.read()

    with open(decrypt_file, 'rb') as decrypt_data:
        dec_data = decrypt_data.read()

    assert in_data == dec_data

    raw_data.close()
    decrypt_data.close()
def reset(session):
    ''' Reset the Secure Module to the initial state. '''
    from sss.se05x import Se05x
    from sss.a71ch import A71CH
    import sss.sss_api as apis
    if session.subsystem == apis.kType_SSS_SE_SE05x:
        se05x_obj = Se05x(session)
        se05x_obj.debug_reset()
    elif session.subsystem == apis.kType_SSS_SE_A71CH:
        a71ch_obj = A71CH(session)
        a71ch_obj.debug_reset()
def set_ecc_pair(session, keyid, client_key):
    ''' Set ECC Key pair to the Secure Module \n
        keyid = 32bit Key ID. Should be in hex format. Example: 20E8A001 \n
        key = Can be raw key (DER format) or in file.
        For file, by default filename with extension .pem considered as PEM format and others as DER format.\n
        '''
    import sss.setkey as setkey
    import sss.sss_api as apis
    log.info("client_key file: %s" % (client_key,))
    log.info("Injecting ECC key pair at key ID: 0x%x" % (keyid,))
    set_obj = setkey.Set(session)
    status = set_obj.do_set_ecc_key_pair(keyid, client_key, None)
    if status != apis.kStatus_SSS_Success:
        log.error("Injecting key pair failed!")
        session_close(session)
        return status
    log.info("Successfully Injected ECC key pair.")
    return status
def set_rsa_pair(session, keyid, client_key):
    ''' Set RSA Key pair to the Secure Module \n
        keyid = 32bit Key ID. Should be in hex format. Example: 20E8A001 \n
        key = Can be raw key (DER format) or in file.
        For file, by default filename with extension .pem considered as PEM format and others as DER format.\n
        '''
    import sss.setkey as setkey
    import sss.sss_api as apis
    log.info("client_key file: %s" % (client_key,))
    log.info("Injecting RSA key pair at key ID: 0x%x" % (keyid,))
    set_obj = setkey.Set(session)
    status = set_obj.do_set_rsa_key_pair(keyid, client_key, None)
    if status != apis.kStatus_SSS_Success:
        log.error("Injecting key pair failed..!")
        session_close(session)
        return status
    log.info("Successfully Injected RSA key pair.")
    return status
def set_ecc_pub(session, keyid, client_key):
    ''' Set ECC Key public part to the Secure Module \n
        keyid = 32bit Key ID. Should be in hex format. Example: 20E8A001 \n
        key = Can be raw key (DER format) or in file.
        For file, by default filename with extension .pem considered as PEM format and others as DER format.\n
        '''
    import sss.setkey as setkey
    import sss.sss_api as apis
    log.info("client_key file: %s" % (client_key,))
    log.info("Injecting ECC public key at key ID: 0x%x" % (keyid,))
    set_obj = setkey.Set(session)
    status = set_obj.do_set_ecc_pub_key(keyid, client_key, None)
    if status != apis.kStatus_SSS_Success:
        log.error("Injecting ECC public key failed!")
        session_close(session)
        return status
    log.info("Successfully Injected ECC public key.")
    return status
def refpem_ecc_pair(session, keyid, file_name):
    ''' Creates reference PEM file for ECC Pair.
        keyid = 32bit Key ID. Should be in hex format. Example: 20E8A001 \n
        filename = File name to store reference key. Can be in PEM or DER or PKCS12 format based on file extension.
        By default filename with extension .pem in PEM format, .pfx or .p12 in PKCS12  format and others in DER format.
    '''
    from sss.refkey import RefPem
    import sss.sss_api as apis
    refpem_obj = RefPem(session)
    status = refpem_obj.do_ecc_refpem_pair(keyid, file_name)
    if status != apis.kStatus_SSS_Success:
        log.error("Refpem creation failed!")
        session_close(session)
        return status
    log.info("Successfully Created reference key.")
    return status
def refpem_rsa(session, keyid, file_name):
    ''' Creates reference PEM file for RSA Pair.
        keyid = 32bit Key ID. Should be in hex format. Example: 20E8A001 \n
        filename = File name to store reference key. Can be in PEM or DER or PKCS12 format based on file extension.
        By default filename with extension .pem in PEM format, .pfx or .p12 in PKCS12  format and others in DER format.
    '''
    from sss.refkey import RefPem
    import sss.sss_api as apis
    refpem_obj = RefPem(session)
    status = refpem_obj.do_rsa_refpem_pair(keyid, file_name)
    if status != apis.kStatus_SSS_Success:
        log.error("Refpem creation failed..!")
        session_close(session)
        return status
    log.info("Successfully Created reference key.")
    return status






