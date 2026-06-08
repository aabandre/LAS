import base64
import json

from app import (
    PS_ENCODING_PREFIX,
    PS_PAYLOAD_PREFIX,
    decode_ps_output,
    is_corrupt_account_name,
    repair_mojibake,
    repair_mojibake_text,
    smart_decode,
)


def _as_gbk_mojibake(value):
    return value.encode("utf-8").decode("gbk")


def _as_latin1_mojibake(value):
    return value.encode("utf-8").decode("latin1")


def _ps_payload(value):
    raw_json = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return (PS_PAYLOAD_PREFIX + base64.b64encode(raw_json).decode("ascii")).encode("ascii")


def test_repairs_cyrillic_misdecoded_as_gbk():
    expected = "Технический сектор (адм)"

    assert repair_mojibake_text(_as_gbk_mojibake(expected)) == expected


def test_repairs_cyrillic_misdecoded_as_latin1():
    expected = "РОССЕТИ-СИБ\\Администраторы"

    assert repair_mojibake_text(_as_latin1_mojibake(expected)) == expected


def test_decodes_ascii_safe_powershell_payload_without_locale_dependency():
    expected = [
        {"Name": "ROSSETI-SIB\\supp_espp", "Type": "User"},
        {"Name": "ROSSETI-SIB\\Технический сектор (адм)", "Type": "Group"},
    ]

    assert json.loads(decode_ps_output(_ps_payload(expected))) == expected


def test_does_not_misclassify_mixed_utf8_as_utf16_cjk_blob():
    damaged = b'["ROSSETI-SIB\\\\G_BA_Admins_AD", "' + b"\xff\xfe\xfa" + b'"]'

    decoded = smart_decode(damaged)

    assert "ROSSETI-SIB" in decoded
    assert "佒卓呅" not in decoded


def test_repairs_nested_winrm_json_values():
    expected = "РОССЕТИ-СИБ\\Технический сектор (адм)"
    payload = [{"Name": _as_gbk_mojibake(expected), "Type": "group"}]
    raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")

    decoded = json.loads(smart_decode(raw))

    assert repair_mojibake(decoded) == [{"Name": expected, "Type": "group"}]


def test_keeps_normal_account_names_unchanged():
    values = [
        "ROSSETI-SIB\\G_BA_Admins_AD",
        "РОССЕТИ-СИБ\\Администраторы",
        "本地管理员",
    ]

    assert repair_mojibake(values) == values


def test_powershell_prefix_does_not_change_native_console_code_page():
    assert "chcp" not in PS_ENCODING_PREFIX.lower()
    assert "Console]::OutputEncoding" not in PS_ENCODING_PREFIX
    assert "Write-LasJson" in PS_ENCODING_PREFIX


def test_rejects_irrecoverably_damaged_account_names():
    assert is_corrupt_account_name("ROSSETI-SIB\\пїЅпїЅеЁпїЅбЄЁпїЅ")
    assert is_corrupt_account_name("≛佒卓呅ⵉ䥓层" * 20)
    assert not is_corrupt_account_name("ROSSETI-SIB\\Технический сектор (адм)")


def test_net_fallback_captures_output_with_windows_oem_encoding():
    source = __import__("pathlib").Path("app.py").read_text(encoding="utf-8")

    assert "StandardOutputEncoding = $oemEncoding" in source
    assert "$raw = net localgroup" not in source
