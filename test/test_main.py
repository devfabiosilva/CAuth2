import pytest
import logging
import panelauth as p
from panelauth import ALG_SHA1, ALG_SHA256, ALG_SHA512, ENTROPY_TYPE_PARANOIC

SIGN_SECRET_KEY = "Secret key 1234567890"
SECRET_KEY_SHA1 = "12345678901234567890"
SECRET_KEY_SHA1_B32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
SECRET_KEY_SHA256_B32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA===="
SECRET_KEY_SHA512_B32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA="
PANEL_AUTH_CLASS_NAME = "Panel Auth"
ERROR_MSG_EXPECTED = "Expected message \"%s\""
MESSAGE = "message to be signed"

def totpValid(value: int) -> bool:
    return ((value >= 0) and (value <= 999999))

def info(msg: str)->None:
    logging.getLogger().info(ERROR_MSG_EXPECTED, msg)

def test_module_with_no_secret_key(caplog) -> None:
    global PANEL_AUTH_CLASS_NAME

    caplog.set_level(logging.INFO)

    with pytest.raises(expected_exception=BaseException, match=PANEL_AUTH_CLASS_NAME) as ex_test:
        p.create(None)

    exception_raised = ex_test.value.__cause__.args[0]
    info(exception_raised)
    assert exception_raised == "Error on parse on init"

def test_module_with_empty_secret_key(caplog) -> None:
    global PANEL_AUTH_CLASS_NAME

    caplog.set_level(logging.INFO)

    with pytest.raises(expected_exception=BaseException, match=PANEL_AUTH_CLASS_NAME) as ex_test:
        p.create("")

    exception_raised = ex_test.value.__cause__.args[0]
    info(exception_raised)
    assert exception_raised == "Empty HMAC secret key"

def test_module_build_date(caplog) -> None:

    caplog.set_level(logging.INFO)

    info(p.buildDate.__doc__)
    info(p.buildDate())
    assert p.buildDate() == "202412122358"

def test_module_get_version(caplog) -> None:

    caplog.set_level(logging.INFO)

    info(p.getVersion.__doc__)
    info(p.getVersion())
    assert p.getVersion() == "0.3.0"

def test_module_get_totp_exception(caplog) -> None:

    caplog.set_level(logging.INFO)

    k = p.create(SIGN_SECRET_KEY)
    info(k.getAuthTotp.__doc__)

    with pytest.raises(expected_exception=BaseException) as ex_test:
        k.getAuthTotp()

    exception_raised = ex_test.value.args[0]
    info(exception_raised)
    assert exception_raised == "Could not get Auth TOTP. Please initilize with Base32 Auth secret key"

def test_module_get_totp_sha1(caplog) -> None:
    global PANEL_AUTH_CLASS_NAME

    caplog.set_level(logging.INFO)

    info("Python3 panelauth only allows Base32 for SHA1 OAuth2")

    with pytest.raises(expected_exception=BaseException, match=PANEL_AUTH_CLASS_NAME) as ex_test:
        p.create(SIGN_SECRET_KEY, SECRET_KEY_SHA1)

    exception_raised = ex_test.value.__cause__.args[0]
    info(exception_raised)
    assert exception_raised == "Empty Auth2 TOTP Base32 secret key or C function check_base32_oauth_key_valid() error"

def test_module_get_totp_sha1_wrong_size(caplog) -> None:
    global PANEL_AUTH_CLASS_NAME

    caplog.set_level(logging.INFO)

    info("Python3 panelauth only allows Base32 for SHA1 OAuth2")

    with pytest.raises(expected_exception=BaseException, match=PANEL_AUTH_CLASS_NAME) as ex_test:
        p.create(SIGN_SECRET_KEY, SECRET_KEY_SHA1_B32, totpAlgType=ALG_SHA256)

    exception_raised = ex_test.value.__cause__.args[0]
    info(exception_raised)
    assert exception_raised == "Empty Auth2 TOTP Base32 secret key or C function check_base32_oauth_key_valid() error"

def test_module_get_totp_sha1_default(caplog) -> None:
    caplog.set_level(logging.INFO)

    info("Python3 panelauth only allows Base32 for SHA1 OAuth2")

    k = p.create(SIGN_SECRET_KEY, SECRET_KEY_SHA1_B32, totpAlgType=ALG_SHA1)
    info(k.getAuthTotp.__doc__)
    value = k.getAuthTotp()
    info(str(value))
    assert totpValid(value)

    m = p.create(SIGN_SECRET_KEY, SECRET_KEY_SHA1_B32)
    value = m.getAuthTotp()
    info(str(value))
    assert totpValid(value)

def test_module_get_totp_sha256_exception(caplog) -> None:

    caplog.set_level(logging.INFO)

    info("Python3 panelauth only allows Base32 for SHA256 OAuth2")

    with pytest.raises(expected_exception=BaseException, match=PANEL_AUTH_CLASS_NAME) as ex_test:
        p.create(SIGN_SECRET_KEY, SECRET_KEY_SHA256_B32)

    exception_raised = ex_test.value.__cause__.args[0]
    info(exception_raised)
    assert exception_raised == "Empty Auth2 TOTP Base32 secret key or C function check_base32_oauth_key_valid() error"

def test_module_get_totp_sha256(caplog) -> None:
    caplog.set_level(logging.INFO)

    info("Python3 panelauth only allows Base32 for SHA256 OAuth2")

    k = p.create(SIGN_SECRET_KEY, SECRET_KEY_SHA256_B32, totpAlgType=ALG_SHA256)
    info(k.getAuthTotp.__doc__)
    value = k.getAuthTotp()
    info(str(value))
    assert totpValid(value)

def test_module_get_totp_sha512_exception(caplog) -> None:

    caplog.set_level(logging.INFO)

    info("Python3 panelauth only allows Base32 for SHA256 OAuth2")

    with pytest.raises(expected_exception=BaseException, match=PANEL_AUTH_CLASS_NAME) as ex_test:
        p.create(SIGN_SECRET_KEY, SECRET_KEY_SHA512_B32)

    exception_raised = ex_test.value.__cause__.args[0]
    info(exception_raised)
    assert exception_raised == "Empty Auth2 TOTP Base32 secret key or C function check_base32_oauth_key_valid() error"

def test_module_get_totp_sha256(caplog) -> None:
    caplog.set_level(logging.INFO)

    info("Python3 panelauth only allows Base32 for SHA512 OAuth2")

    k = p.create(SIGN_SECRET_KEY, SECRET_KEY_SHA512_B32, totpAlgType=ALG_SHA512)
    info(k.getAuthTotp.__doc__)
    value = k.getAuthTotp()
    info(str(value))
    assert totpValid(value)

def test_module_sign_message_sha1(caplog) -> None:
    caplog.set_level(logging.INFO)

    k = p.create(SIGN_SECRET_KEY, hmacAlgType=ALG_SHA1)

    signed_message = k.signMessage(MESSAGE)
    assert len(signed_message) == 20

    signed_message_str = signed_message.hex().lower()
    info(signed_message_str)

    assert signed_message_str == "9459c4875d2fee1f596f16ddb0323c86a97f6373"

def test_module_sign_message_sha256(caplog) -> None:
    caplog.set_level(logging.INFO)

    k = p.create(SIGN_SECRET_KEY)

    signed_message = k.signMessage(MESSAGE)
    assert len(signed_message) == 32

    signed_message_str = signed_message.hex().lower()
    info(signed_message_str)

    assert signed_message_str == "a3e3760ece4d5e5a3af3f46fdecdca641870e56465d9fcd60e663fcd0ef42675"

def test_module_sign_message_sha512(caplog) -> None:
    caplog.set_level(logging.INFO)

    k = p.create(SIGN_SECRET_KEY, hmacAlgType=ALG_SHA512)

    signed_message = k.signMessage(MESSAGE)
    assert len(signed_message) == 64

    signed_message_str = signed_message.hex().lower()
    info(signed_message_str)

    assert signed_message_str == "306f1a088b72a0d6e11b435a709af7fec9a9cce5cf1519f3fb1c4e395c7921ba43cca697821bdadf27bef1acd4315a6e807492eaf49f1130342e21cdf45e5ca2"

# TODO IMPLEMENT THIS FAILING TESTS
def ignore_test_generate_key_execptions(caplog) -> None:
    caplog.set_level(logging.INFO)

    with pytest.raises(expected_exception=BaseException, match="PANEL_AUTH module") as ex_test:
        p.genkey("abc")

    exception_raised = ex_test.value.__cause__.args[0]
    info(exception_raised)
    assert exception_raised == "Error on parse on init"

def test_generate_key_sha512(caplog) -> None:
    caplog.set_level(logging.INFO)

    genkey1 = p.genKey()
    assert genkey1 != None
    assert len(genkey1) == 64

    info(genkey1.hex().upper())

    genkey2 = p.genKey(entropyType = ENTROPY_TYPE_PARANOIC)

    assert genkey2 != None
    assert len(genkey2) == 64
    assert genkey2 != genkey1

    info(genkey2.hex().upper())

    genkey3 = p.genKey(ALG_SHA512, ENTROPY_TYPE_PARANOIC)

    assert genkey3 != None
    assert len(genkey2) == 64
    assert genkey3 != genkey2

    info(genkey3.hex().upper())

def test_generate_key_sha256(caplog) -> None:
    caplog.set_level(logging.INFO)

    genkey1 = p.genKey(ALG_SHA256)

    assert genkey1 != None
    assert len(genkey1) == 32

    info(genkey1.hex().upper())

    genkey2 = p.genKey(ALG_SHA256, entropyType = ENTROPY_TYPE_PARANOIC)

    assert genkey2 != None
    assert genkey2 != genkey1
    assert len(genkey2) == 32

    info(genkey2.hex().upper())

    genkey3 = p.genKey(ALG_SHA256, ENTROPY_TYPE_PARANOIC)

    assert genkey3 != None
    assert len(genkey3) == 32
    assert genkey3 != genkey2

    info(genkey3.hex().upper())

def test_generate_key_sha1(caplog) -> None:
    caplog.set_level(logging.INFO)

    genkey1 = p.genKey(ALG_SHA1)

    assert genkey1 != None
    assert len(genkey1) == 20

    info(genkey1.hex().upper())

    genkey2 = p.genKey(ALG_SHA1, entropyType = ENTROPY_TYPE_PARANOIC)

    assert genkey2 != None
    assert genkey2 != genkey1
    assert len(genkey2) == 20

    info(genkey2.hex().upper())

    genkey3 = p.genKey(ALG_SHA1, ENTROPY_TYPE_PARANOIC)

    assert genkey3 != None
    assert len(genkey3) == 20
    assert genkey3 != genkey2

    info(genkey3.hex().upper())

def test_generate_totp_key_sha512(caplog) -> None:
    caplog.set_level(logging.INFO)

    genkey1 = p.genTOTPKey()
    assert genkey1 != None
    assert len(genkey1) == 103

    info(genkey1)

    genkey2 = p.genTOTPKey(entropyType = ENTROPY_TYPE_PARANOIC)

    assert genkey2 != None
    assert len(genkey2) == 103
    assert genkey2 != genkey1

    info(genkey2)

    genkey3 = p.genTOTPKey(ALG_SHA512, ENTROPY_TYPE_PARANOIC)

    assert genkey3 != None
    assert len(genkey2) == 103
    assert genkey3 != genkey2

    info(genkey3)

def test_generate_totp_key_sha256(caplog) -> None:
    caplog.set_level(logging.INFO)

    genkey1 = p.genTOTPKey(ALG_SHA256)

    assert genkey1 != None
    assert len(genkey1) == 55

    info(genkey1)

    genkey2 = p.genTOTPKey(ALG_SHA256, entropyType = ENTROPY_TYPE_PARANOIC)

    assert genkey2 != None
    assert genkey2 != genkey1
    assert len(genkey2) == 55

    info(genkey2)

    genkey3 = p.genTOTPKey(ALG_SHA256, ENTROPY_TYPE_PARANOIC)

    assert genkey3 != None
    assert len(genkey3) == 55
    assert genkey3 != genkey2

    info(genkey3)

def test_generate_totp_key_sha1(caplog) -> None:
    caplog.set_level(logging.INFO)

    genkey1 = p.genTOTPKey(ALG_SHA1)

    assert genkey1 != None
    assert len(genkey1) == 31

    info(genkey1)

    genkey2 = p.genTOTPKey(ALG_SHA1, entropyType = ENTROPY_TYPE_PARANOIC)

    assert genkey2 != None
    assert genkey2 != genkey1
    assert len(genkey2) == 31

    info(genkey2)

    genkey3 = p.genTOTPKey(ALG_SHA1, ENTROPY_TYPE_PARANOIC)

    assert genkey3 != None
    assert len(genkey3) == 31
    assert genkey3 != genkey2

    info(genkey3)

