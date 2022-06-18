import panelauth as p
import pytest
import logging

SECRET_KEY_SHA1 = "12345678901234567890"
SECRET_KEY_SHA1_B32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
PANEL_AUTH_CLASS_NAME = "Panel Auth"
ERROR_MSG_EXPECTED = "Expected message \"%s\""

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
    global PANEL_AUTH_CLASS_NAME

    caplog.set_level(logging.INFO)

    k = p.create("Secret key")

    info(k.buildDate.__doc__)
    info(k.buildDate())
    assert k.buildDate() == "202206011949"
