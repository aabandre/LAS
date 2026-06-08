import json

from app import repair_mojibake, repair_mojibake_text, smart_decode


def _as_gbk_mojibake(value):
    return value.encode("utf-8").decode("gbk")


def _as_latin1_mojibake(value):
    return value.encode("utf-8").decode("latin1")


def test_repairs_cyrillic_misdecoded_as_gbk():
    expected = "Технический сектор (адм)"

    assert repair_mojibake_text(_as_gbk_mojibake(expected)) == expected


def test_repairs_cyrillic_misdecoded_as_latin1():
    expected = "РОССЕТИ-СИБ\\Администраторы"

    assert repair_mojibake_text(_as_latin1_mojibake(expected)) == expected


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
