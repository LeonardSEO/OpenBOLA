from pathlib import Path

ROOT = Path(__file__).parents[1]


def test_installers_are_local_checksum_first_and_prompt_safe() -> None:
    shell = (ROOT / "packaging" / "install.sh").read_text()
    powershell = (ROOT / "packaging" / "install.ps1").read_text()
    assert "shasum -a 256" in shell
    assert "--no-path" in shell
    assert "sudo" not in shell
    assert "Get-FileHash" in powershell
    assert "-NoPath" in powershell
    assert "Move-Item" in powershell
    for forbidden in ("Invoke-WebRequest", "Start-BitsTransfer"):
        assert forbidden not in powershell
    assert " irm " not in powershell.lower()
    assert "curl " not in powershell.lower()
