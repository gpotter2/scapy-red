"""Tests for the winreg module in scapy-red."""

import pytest
from scapyred.winreg import RegClient
from scapy.layers.windows.registry import RegEntry, RegType
from scapy.layers.windows.security import SECURITY_DESCRIPTOR
from pathlib import PureWindowsPath


@pytest.fixture
def test_regclient_initialization():
    """Test the initialization of RegClient with given parameters."""
    client = RegClient(
        "127.0.0.1",
        UPN="Admin@WORKGROUP",
        password="HolaQuetal123",
        domain="Workgroup",
        kerberos=False,
        cli=False,
        debug=True,
    )
    assert client.client is not None
    assert isinstance(client, RegClient)
    return client


@pytest.fixture
def test_use(test_regclient_initialization):
    """Test the use method of RegClient."""
    client = test_regclient_initialization

    # Test with valid root keys
    for root_key in ["HKLM", "HKCU", "HKCR", "HKU", "HKCC"]:
        result = client.use(root_key)
        print(f"Switched to root key: {root_key} with result: {result}")
        assert result is not None

    # Test with an invalid root key
    with pytest.raises(ValueError, match="'HKEY_INVALID' is not a valid RootKeys"):
        client.use("HKEY_INVALID")

    # Return the client for further tests
    client.use("HKLM")
    return client


@pytest.fixture
def test_cd(test_use):
    """Test the cd method of RegClient."""
    client = test_use

    # Change to a valid subkey
    try:
        result = client.cd("\\SOFTWARE\\Microsoft\\Windows\\")
        result = client.cd("..")
        result = client.cd("Windows\\CurrentVersion")
        result = client.cd("\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion")
        print(
            f"Changed directory to SOFTWARE\\Microsoft\\Windows\\CurrentVersion with result: {result}"
        )
        assert client.current_subkey_path == PureWindowsPath(
            "SOFTWARE/Microsoft/Windows/CurrentVersion"
        )
    except ValueError as exc:
        pytest.fail(f"cd method raised an exception unexpectedly!: {exc}")

    # Attempt to change to an invalid subkey
    with pytest.raises(
        ValueError, match="Could not change directory to SOFTWARE\\\\NonExistentKey"
    ):
        client.cd("SOFTWARE\\NonExistentKey")

    client.cd("")
    return client


def test_ls(test_cd):
    """Test the ls method of RegClient."""
    client = test_cd

    # List subkeys and values in the current directory
    list_of_first_subkeys = client.ls()

    assert set(list_of_first_subkeys).issuperset(
        {
            "BCD00000000",
            "HARDWARE",
            "SAM",
            "SECURITY",
            "SOFTWARE",
            "SYSTEM",
        }
    )

    list_of_subkeys = client.ls("SOFTWARE\\Microsoft\\Windows NT")
    assert "CurrentVersion" in list_of_subkeys


def test_cat(test_cd):
    """Test the cat method of RegClient."""
    client = test_cd

    # Read a known registry value
    value_data: list[RegEntry] = client.cat(
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
    )
    assert len(value_data) > 30  # Expecting multiple values
    registered_owner = next(
        (
            entry
            for entry in value_data
            if entry.reg_name == "CurrentMajorVersionNumber"
        ),
        None,
    )
    display_version = next(
        (entry for entry in value_data if entry.reg_name == "SystemRoot"), None
    )
    edition_id = next(
        (entry for entry in value_data if entry.reg_name == "EditionID"), None
    )
    assert all(
        [
            registered_owner is not None,
            display_version is not None,
            edition_id is not None,
        ]
    )


def test_get_sd(test_cd):
    """Test retrieving a security descriptor from the registry."""
    client = test_cd

    sd = client.get_sd("SAM")
    assert isinstance(sd, SECURITY_DESCRIPTOR)

    sd = client.get_sd("SECURITY")
    assert sd is None

    client.backup(activate=True)
    sd = client.get_sd("SECURITY")
    assert isinstance(sd, SECURITY_DESCRIPTOR)


def test_query_info(test_cd):
    """Test querying information about a registry key."""
    client = test_cd

    info = client.query_info()
    assert info is not None
    assert info.lpcSubKeys >= 6
    assert info.lpcbMaxSubKeyLen >= 22
    assert info.lpftLastWriteTime is not None


def test_version(test_cd):
    """Test retrieving the Windows version from the registry."""
    client = test_cd

    version = client.version()
    assert version == 6


@pytest.fixture
def test_create_key(test_cd):
    """Test creating / deleting a registry key."""
    client = test_cd

    # Create a new key
    client.create_key("ScapyRedTestKey", "SOFTWARE")
    subkeys = client.ls("SOFTWARE")
    assert "ScapyRedTestKey" in subkeys
    client.delete_key("SOFTWARE\\ScapyRedTestKey")
    subkeys = client.ls("SOFTWARE")
    assert "ScapyRedTestKey" not in subkeys
    client.create_key("ScapyRedTestKey", "SOFTWARE")

    return client


@pytest.fixture
def test_value(test_create_key):
    """Test setting and getting a registry value."""
    client = test_create_key
    # Set a value in the created key
    reg_entry = [
        RegEntry(
            reg_name="ScapyValueSZ",
            reg_type=RegType(1),  # REG_SZ
            reg_data="ScapyRedTestData",
        ),
        RegEntry(
            reg_name="ScapyValueExpandSz",
            reg_type=RegType(2),  # REG_EXPAND_SZ
            reg_data="%SystemRoot%\\System32",
        ),
        RegEntry(
            reg_name="ScapyValueBinary",
            reg_type=RegType(3),  # REG_BINARY
            reg_data=b"\xde\xad\xbe\xef",
        ),
        RegEntry(
            reg_name="ScapyValueDword",
            reg_type=RegType(4),  # REG_DWORD
            reg_data=99,
        ),
        RegEntry(
            reg_name="ScapyValueDwordBigEndian",
            reg_type=RegType(5),  # REG_DWORD_BIG_ENDIAN
            reg_data=654321,
        ),
        RegEntry(
            reg_name="ScapyValueLink",
            reg_type=RegType(6),  # REG_LINK
            reg_data="\\??\\C:\\Windows\\System32",
        ),
        RegEntry(
            reg_name="ScapyValueMultiSz",
            reg_type=RegType(7),  # REG_MULTI_SZ
            reg_data=["String1", "String2", "String3"],
        ),
        RegEntry(
            reg_name="ScapyValueQword",
            reg_type=RegType(11),  # REG_QWORD
            reg_data=123456789012345,
        ),
    ]

    client.backup(activate=True)
    for entry in reg_entry:
        print(entry.reg_data)
        client.set_value(
            entry.reg_name,
            entry.reg_type,
            entry.reg_data,
            subkey="SOFTWARE\\ScapyRedTestKey",
        )

    assert len(client.cat("SOFTWARE\\ScapyRedTestKey")) == len(reg_entry)
    for entry in client.cat("SOFTWARE\\ScapyRedTestKey"):
        matching_entry = next(
            (e for e in reg_entry if e.reg_name == entry.reg_name), None
        )
        assert matching_entry is not None
        assert matching_entry.reg_type == entry.reg_type
        assert matching_entry.reg_data == entry.reg_data

    return client


def test_delete_value(test_value):
    """
    Test the value deletion
    """

    client = test_value
    cat = client.cat("SOFTWARE\\ScapyRedTestKey")
    value_sz = RegEntry(
        reg_name="ScapyValueSZ",
        reg_type=RegType(1),  # REG_SZ
        reg_data="ScapyRedTestData",
    )

    assert value_sz in cat
    client.delete_value(value=value_sz.reg_name, subkey="SOFTWARE\\ScapyRedTestKey")
    cat = client.cat("SOFTWARE\\ScapyRedTestKey")
    assert value_sz not in cat


def test_save(test_use):
    """Test saving registry key"""
    client = test_use

    try:
        success = client.save(output_path="C:\\", subkey="SOFTWARE")
    except ValueError as exc:
        pytest.fail(f"raised an exception unexpectedly!: {exc}")

    assert success
