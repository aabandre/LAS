from remediation import _build_remediation_winrm_script, _remediation_group_sid


def test_winrm_remediation_script_is_a_string_not_a_tuple():
    script = _build_remediation_winrm_script(
        "Administrators",
        r"ROSSETI-SIB\test_user",
        "S-1-5-21-100-200-300-1105",
    )

    assert isinstance(script, str)
    assert "NetLocalGroupDelMembers" in script
    assert "LAS-RESULT:" in script
    assert "Member is still present after SID removal" in script


def test_builtin_group_name_resolves_to_well_known_sid():
    assert _remediation_group_sid("Administrators") == "S-1-5-32-544"
    assert _remediation_group_sid("Пользователи удаленного рабочего стола") == "S-1-5-32-555"
