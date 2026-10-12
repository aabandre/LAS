from pathlib import Path


def test_exported_remediation_template_has_no_broken_group_sid_resolver():
    template = Path(__file__).resolve().parents[1] / "templates" / "summary.html"
    source = template.read_text(encoding="utf-8")

    # This malformed fragment previously leaked into downloaded .ps1 files and
    # made Windows PowerShell stop parsing the script before any deletion ran.
    assert "(?i:Administrators)else{''" not in source
    assert "(?i:Administrators|Администраторы)" not in source

    # Resolve the built-in Administrators group by its invariant SID, without
    # requiring the target machine's localized display name.
    assert "elseif($RequestedGroup -ieq 'Administrators'){$groupSid='S-1-5-32-544'}" in source
    assert "elseif($Group -ieq 'Administrators'){$groupSid='S-1-5-32-544'}" in source
