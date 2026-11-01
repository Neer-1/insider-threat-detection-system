# NEW — single .env loading point, so every module that reads a secret via
# os.getenv() sees it regardless of which one happens to import first.

"""
Previously SECRET_KEY (core/config.py) and DATABASE_URL (database/db.py)
each just called os.getenv() directly against real OS environment
variables, with no .env file support at all -- fine when there was
nothing to persist locally beyond what a shell profile could hold. Added
now because SMTP_ENCRYPTION_KEY is a real secret worth keeping in one
actual file rather than re-exporting by hand every session, and it made
no sense to introduce a SECOND config-loading pattern alongside the
existing one -- SECRET_KEY/DATABASE_URL move onto this same mechanism in
the same change, not left as a separate precedent.

load_dotenv() only ever SETS a variable that isn't already present in the
real environment (its default override=False) -- an operator who already
exports SECRET_KEY/DATABASE_URL/etc. via their shell or systemd unit
keeps taking priority over anything sitting in a .env file, matching how
every other env-based config here has always behaved.

Every module that reads a secret via os.getenv() must import this module
FIRST (before its own os.getenv calls) -- `from backend.core import env`
at the top, before `import os`-based reads. Importing it more than once
across different modules is harmless: load_dotenv() itself is idempotent,
and Python only actually executes a module's top-level code once no
matter how many times it's imported.
"""

from dotenv import load_dotenv

from pathlib import Path
import os

if os.getenv("PYTHON_DOTENV_DISABLED") != "1":
    load_dotenv(Path(__file__).resolve().parents[2] / ".env", override=False)
