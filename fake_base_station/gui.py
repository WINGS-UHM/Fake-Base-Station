"""Launcher shim so `python -m fake_base_station.gui` works from repo root."""

from __future__ import annotations

from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path


def _load_impl():
    repo_root = Path(__file__).resolve().parents[1]
    impl_path = repo_root / "src" / "fake_base_station" / "gui.py"

    if not impl_path.exists():
        raise FileNotFoundError(f"GUI implementation not found: {impl_path}")

    spec = spec_from_file_location("_fake_base_station_gui_impl", str(impl_path))
    if spec is None or spec.loader is None:
        raise RuntimeError("Failed to load GUI implementation spec")

    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_impl = _load_impl()

PcapPacketLoader = _impl.PcapPacketLoader
ModifiedPcapReplayer = _impl.ModifiedPcapReplayer
NGAPPcapGui = _impl.NGAPPcapGui
_extract_message_name = _impl._extract_message_name
main = _impl.main


if __name__ == "__main__":
    main()
