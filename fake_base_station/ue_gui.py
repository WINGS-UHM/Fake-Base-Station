"""Wrapper module to re-export UE GUI from src."""
import sys
import importlib.util
from pathlib import Path

# Load the actual implementation from src/fake_base_station/ue_gui.py
src_ue_gui_path = Path(__file__).parent.parent / "src" / "fake_base_station" / "ue_gui.py"
spec = importlib.util.spec_from_file_location("_ue_gui_impl", src_ue_gui_path)
_ue_gui_impl = importlib.util.module_from_spec(spec)
spec.loader.exec_module(_ue_gui_impl)

# Re-export classes and main function
UEGapGui = _ue_gui_impl.UEGapGui
PacketListener = _ue_gui_impl.PacketListener
main = _ue_gui_impl.main

__all__ = ["UEGapGui", "PacketListener", "main"]

if __name__ == "__main__":
    main()
