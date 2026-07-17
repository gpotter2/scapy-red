# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy RED
# See https://scapy.net/ for more information
# Copyright (C) github/Ebrix

r"""
Declarative registry module runner.

``scapy-regmodule`` applies a *module file* - a small declarative TOML document
describing a title, a short name, a target key and a list of actions - to a
remote Windows registry over MS-RRP. It is a thin driver on top of
:class:`scapyred.winreg.RegClient` (in scripting mode, ``cli=False``): every
action maps to an existing ``RegClient`` method, so no registry/RPC logic is
re-implemented here.

A module is selected either by its short name (``--module rdp-on``), which scans
the built-in :mod:`scapyred.modules` directory plus any user directories, or by
an explicit path (``--file ./mymod.toml``). ``--list`` enumerates the modules
that can be found.

Module file schema (TOML)::

    title = "Enable RDP"
    short = "rdp-on"
    key   = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server"

    [[actions]]
    op   = "set_value"
    name = "fDenyTSConnections"
    type = "REG_DWORD"
    data = "0"

``key`` is a full path beginning with a root abbreviation (``HKLM``, ``HKCU``,
``HKU``, ``HKCR``, ``HKCC``, ``HKPD``, ``HKPT``, ``HKPN``). It is the default
target for every action; an action may override it with its own ``key``.

Supported ``op`` values:

    - ``set_value``   (``name``, ``type``, ``data``)  -> set a value
    - ``create_key``  (target ``key`` is the key to create)
    - ``delete_value``(``name``)                      -> delete a value
    - ``delete_key``  (target ``key`` is the key to delete)
    - ``list``                                        -> enumerate subkeys
    - ``cat``                                         -> dump all values
    - ``read``        (``name``)                      -> read one named value
    - ``enum``        (``values``)                    -> for each subkey, read
      the listed value names (e.g. list installed software from the Uninstall
      keys); with no ``values`` it just lists the subkey names

Only ``set_value``, ``create_key``, ``delete_value`` and ``delete_key`` mutate
the registry; running a module that contains any of them prompts for
confirmation unless ``--yes`` (or ``--dry-run``) is given.
"""

import os
import pathlib
import tomllib

from scapy.config import conf
from scapy.error import log_runtime
from scapy.layers.windows.registry import RootKeys

from scapyred.winreg import AVAILABLE_ROOT_KEYS, RegClient


# Actions that change the registry. A module containing any of these is
# considered "mutating" and triggers the confirmation prompt.
_MUTATING_OPS = {"set_value", "create_key", "delete_value", "delete_key"}

# op -> extra required action fields (beyond `op`/`key`).
_REQUIRED_FIELDS = {
    "set_value": ("name", "type", "data"),
    "create_key": (),
    "delete_value": ("name",),
    "delete_key": (),
    "list": (),
    "cat": (),
    "read": ("name",),
    "enum": (),
}

# The built-in modules shipped inside the package.
_BUILTIN_MODULES_DIR = pathlib.Path(__file__).parent / "modules"


def _module_search_dirs(modules_dir: str | None) -> list[pathlib.Path]:
    """
    Directories scanned for module files, most-specific first: the ``--modules-dir``
    argument, then the ``SCAPY_RED_MODULES`` environment variable (``os.pathsep``
    separated), then the built-in :data:`_BUILTIN_MODULES_DIR`.
    """
    dirs: list[pathlib.Path] = []
    if modules_dir:
        dirs.append(pathlib.Path(modules_dir))
    env = os.environ.get("SCAPY_RED_MODULES")
    if env:
        dirs.extend(pathlib.Path(p) for p in env.split(os.pathsep) if p)
    dirs.append(_BUILTIN_MODULES_DIR)
    # Keep only existing directories, de-duplicated while preserving order.
    seen: set[pathlib.Path] = set()
    out: list[pathlib.Path] = []
    for d in dirs:
        rd = d.resolve()
        if rd not in seen and d.is_dir():
            seen.add(rd)
            out.append(d)
    return out


def _validate_module(data: dict, source: str) -> dict:
    """
    Validate a parsed module mapping and return it unchanged.

    :param data: the parsed TOML mapping.
    :param source: a human-readable origin (path) for error messages.
    :raises ValueError: if a required field is missing or an action is malformed.
    """
    for field in ("title", "short", "actions"):
        if field not in data:
            raise ValueError(f"{source}: missing required field '{field}'")
    if not isinstance(data["actions"], list) or not data["actions"]:
        raise ValueError(f"{source}: 'actions' must be a non-empty array")

    module_key = data.get("key")
    for i, action in enumerate(data["actions"]):
        if not isinstance(action, dict) or "op" not in action:
            raise ValueError(f"{source}: action #{i + 1} must be a table with an 'op'")
        op = action["op"]
        if op not in _REQUIRED_FIELDS:
            raise ValueError(
                f"{source}: action #{i + 1} has unknown op '{op}' "
                f"(expected one of {', '.join(sorted(_REQUIRED_FIELDS))})"
            )
        if not action.get("key") and not module_key:
            raise ValueError(
                f"{source}: action #{i + 1} ('{op}') has no 'key' and the module "
                f"defines no default 'key'"
            )
        for field in _REQUIRED_FIELDS[op]:
            if field not in action:
                raise ValueError(
                    f"{source}: action #{i + 1} ('{op}') is missing field '{field}'"
                )
        if op == "enum" and "values" in action and not isinstance(
            action["values"], list
        ):
            raise ValueError(
                f"{source}: action #{i + 1} ('enum') 'values' must be an array"
            )
    return data


def _load_module_file(path: pathlib.Path) -> dict:
    """
    Parse and validate a single module file.

    :param path: path to the ``.toml`` module file.
    :return: the validated module mapping.
    :raises ValueError: if the file cannot be parsed or fails validation.
    """
    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ValueError(f"{path}: could not read module file ({exc})")
    return _validate_module(data, str(path))


def _discover_modules(modules_dir: str | None) -> list[tuple[pathlib.Path, dict]]:
    """
    Load every ``*.toml`` module reachable from the search dirs. Malformed files
    are skipped with a warning rather than aborting discovery.
    """
    found: list[tuple[pathlib.Path, dict]] = []
    for d in _module_search_dirs(modules_dir):
        for path in sorted(d.glob("*.toml")):
            try:
                found.append((path, _load_module_file(path)))
            except ValueError as exc:
                log_runtime.warning("Skipping invalid module: %s", exc)
    return found


def _resolve_module(short: str, modules_dir: str | None) -> tuple[pathlib.Path, dict]:
    """
    Find a module by its ``short`` name across the search dirs. The first match
    (search dirs are most-specific first) wins.

    :raises ValueError: if no module with that short name is found.
    """
    for path, data in _discover_modules(modules_dir):
        if data.get("short") == short:
            return path, data
    raise ValueError(
        f"No module with short name '{short}' found. "
        f"Use --list to see available modules."
    )


def _split_key(key: str) -> tuple[str, str]:
    """
    Split a full registry path into its root abbreviation and the relative subpath.

    :example:
        ``_split_key("HKLM\\SYSTEM\\Foo")`` -> ``("HKLM", "SYSTEM\\Foo")``
        ``_split_key("HKLM")``               -> ``("HKLM", "")``

    :raises ValueError: if the root is not a recognized root key.
    """
    normalized = key.replace("/", "\\").strip().lstrip("\\")
    root, _, subpath = normalized.partition("\\")
    try:
        root_enum = RootKeys(root)
    except ValueError:
        valid = ", ".join(str(r.value) for r in AVAILABLE_ROOT_KEYS)
        raise ValueError(f"Unknown root key '{root}' in '{key}' (expected one of {valid})")
    return str(root_enum.value), subpath.strip("\\")


def _describe_action(action: dict, default_key: str | None) -> str:
    """Render a single action as a one-line human-readable preview string."""
    op = action["op"]
    key = action.get("key", default_key)
    if op == "set_value":
        return f"set_value   {key}  {action['name']} = ({action['type']}) {action['data']!r}"
    if op == "create_key":
        return f"create_key  {key}"
    if op == "delete_value":
        return f"delete_value {key}  {action['name']}"
    if op == "delete_key":
        return f"delete_key  {key}"
    if op == "read":
        return f"read        {key}  {action['name']}"
    if op == "enum":
        vals = action.get("values")
        suffix = f"  [{', '.join(vals)}]" if vals else ""
        return f"enum        {key}{suffix}"
    return f"{op:<11} {key}"


def _module_mutates(data: dict) -> bool:
    """True if any action in the module changes the registry."""
    return any(action["op"] in _MUTATING_OPS for action in data["actions"])


def _print_preview(data: dict, path: pathlib.Path) -> None:
    """Print the module header and the list of actions it will perform."""
    ct = conf.color_theme
    print(ct.bold(f"Module: {data['title']} ({data['short']})"))
    print(f"  file: {path}")
    if data.get("key"):
        print(f"  key : {data['key']}")
    print(f"  {len(data['actions'])} action(s):")
    for action in data["actions"]:
        print("    - " + _describe_action(action, data.get("key")))


def _apply_enum(client: RegClient, action: dict, root: str, subpath: str) -> None:
    """
    Handle the ``enum`` op: enumerate the subkeys of ``subpath`` and, for each,
    read the value names listed in the action's optional ``values`` field. Rows
    whose subkey exposes none of the requested values are skipped (this filters
    housekeeping subkeys out of e.g. an installed-software listing). With no
    ``values``, it simply lists the subkey names.
    """
    wanted = action.get("values")
    subs = client.ls(subkey=subpath)
    print(f"[{root}\\{subpath}] {len(subs)} subkey(s):")
    if not wanted:
        for name in subs:
            print(f"  {name}")
        return
    shown = 0
    for name in subs:
        child = f"{subpath}\\{name}" if subpath else name
        entries = {e.reg_name: e for e in client.cat(subkey=child)}
        if not any(v in entries for v in wanted):
            continue
        cols = "  ".join(
            str(entries[v].reg_data).strip() if v in entries else "-" for v in wanted
        )
        print(f"  {cols}")
        shown += 1
    print(f"  ({shown} entr{'y' if shown == 1 else 'ies'} with {'/'.join(wanted)})")


def _apply_action(client: RegClient, action: dict, default_key: str | None) -> bool:
    """
    Dispatch a single action to the matching :class:`RegClient` method, using the
    action's ``key`` (or the module default) as target. ``client.use()`` selects
    the root; ``subkey`` is the path relative to that root.

    :return: True on success, False on failure.
    """
    op = action["op"]
    key = action.get("key", default_key)
    root, subpath = _split_key(key)

    # Select the root hive for this action.
    if client.use(root) is None:
        log_runtime.error("Could not open root key %s", root)
        return False

    try:
        if op == "set_value":
            client.set_value(
                action["name"], action["type"], str(action["data"]), subkey=subpath
            )
        elif op == "create_key":
            # subpath is the full new key path: split into parent + leaf.
            leaf = pathlib.PureWindowsPath(subpath).name
            parent = str(pathlib.PureWindowsPath(subpath).parent)
            parent = "" if parent == "." else parent
            client.create_key(leaf, subkey=parent)
        elif op == "delete_value":
            client.delete_value(action["name"], subkey=subpath)
        elif op == "delete_key":
            client.delete_key(subkey=subpath)
        elif op == "list":
            print(f"[{root}\\{subpath}] subkeys:")
            client.ls_output(client.ls(subkey=subpath))
        elif op == "cat":
            print(f"[{root}\\{subpath}] values:")
            client.cat_output(client.cat(subkey=subpath))
        elif op == "read":
            wanted = action["name"]
            entries = [e for e in client.cat(subkey=subpath) if e.reg_name == wanted]
            if entries:
                client.cat_output(entries)
            else:
                print(f"Value '{wanted}' not found under {root}\\{subpath}")
        elif op == "enum":
            _apply_enum(client, action, root, subpath)
    except Exception as exc:
        log_runtime.error("Action '%s' on %s failed: %s", op, key, exc)
        return False
    return True


def regmodule(
    target: str = None,
    module: str = None,
    file: str = None,
    list: bool = False,
    modules_dir: str = None,
    dry_run: bool = False,
    yes: bool = False,
    UPN: str = None,
    password: str = None,
    kerberos: bool = True,
    kerberos_required: bool = False,
    HashNt: str = None,
    HashAes128Sha96: str = None,
    HashAes256Sha96: str = None,
    use_krb5ccname: bool = False,
    use_winssp: bool = False,
    port: int = 445,
    timeout: int = 2,
    debug: int = 0,
) -> None:
    r"""
    Apply a declarative registry module to a remote host.

    :param target: hostname, IPv4 or IPv6 of the host to connect to.
    :param module: short name of the module to run (scans the module dirs).
    :param file: path to a module file to run directly (bypasses --module).
    :param list: list the available modules and exit (no connection).
    :param modules_dir: an extra directory to scan for modules.
    :param dry_run: print the resolved actions and exit without connecting.
    :param yes: do not prompt for confirmation before mutating the registry.
    :param UPN: the upn to use (DOMAIN/USER, DOMAIN\USER, USER@DOMAIN or USER).
    :param password: if provided, used for auth.
    :param kerberos: if available, whether to use Kerberos or not.
    :param kerberos_required: require kerberos.
    :param HashNt: if provided, used for auth (NTLM).
    :param HashAes128Sha96: if provided, used for auth (Kerberos).
    :param HashAes256Sha96: if provided, used for auth (Kerberos).
    :param use_krb5ccname: if true, use the KRB5CCNAME environment variable.
    :param use_winssp: (Windows only) use implicit authentication through WinSSP.
    :param port: the TCP port. default 445.
    :param timeout: connection timeout in seconds.
    :param debug: set > 0 for debug logging.
    """

    # --list: enumerate modules and stop, no connection needed.
    if list:
        modules = _discover_modules(modules_dir)
        if not modules:
            print("No modules found.")
            return
        print(f"{'SHORT':<20} {'TITLE':<40} KEY")
        for path, data in modules:
            print(
                f"{data.get('short', '?'):<20} {data.get('title', '?'):<40} "
                f"{data.get('key', '')}"
            )
        return

    # Resolve the module to run, either from an explicit file or by short name.
    if file:
        path = pathlib.Path(file)
        data = _load_module_file(path)
    elif module:
        path, data = _resolve_module(module, modules_dir)
    else:
        raise ValueError("Provide --module <short>, --file <path>, or --list.")

    _print_preview(data, path)

    mutates = _module_mutates(data)
    if dry_run:
        print("\n[dry-run] not connecting; no actions performed.")
        return

    # Confirmation gate: only when the module actually changes the registry.
    if mutates and not yes:
        answer = input("\nThis module modifies the registry. Proceed? [y/N] ")
        if answer.strip().lower() not in ("y", "yes"):
            print("Aborted.")
            return

    if not target:
        raise ValueError("A --target is required to run a module.")

    client = RegClient(
        target,
        UPN=UPN,
        password=password,
        kerberos=kerberos,
        kerberos_required=kerberos_required,
        HashNt=HashNt,
        HashAes128Sha96=HashAes128Sha96,
        HashAes256Sha96=HashAes256Sha96,
        use_krb5ccname=use_krb5ccname,
        use_winssp=use_winssp,
        port=port,
        timeout=timeout,
        debug=debug,
        cli=False,
    )

    ok = 0
    try:
        for i, action in enumerate(data["actions"]):
            print(f"\n[{i + 1}/{len(data['actions'])}] {action['op']}")
            if _apply_action(client, action, data.get("key")):
                ok += 1
    finally:
        client.close()

    total = len(data["actions"])
    print(f"\nDone: {ok}/{total} action(s) succeeded.")


def main():
    """
    Main entry point
    """
    from scapy.utils import AutoArgparse

    conf.exts.load("scapy-red")
    AutoArgparse(regmodule)


# For autocompletion generation
AUTOCOMPLETE_GEN = regmodule

if __name__ == "__main__":
    main()
