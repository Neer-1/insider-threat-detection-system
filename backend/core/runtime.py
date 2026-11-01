"""Explicit opt-ins for the academic release; defaults make no external calls."""
import os
BACKGROUND_ANALYSIS = os.getenv("LITDS_BACKGROUND_ANALYSIS", "0") == "1"
EXTERNAL_SERVICES = os.getenv("LITDS_EXTERNAL_SERVICES", "0") == "1"
