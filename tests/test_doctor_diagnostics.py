"""Regression test for A8: `doctor` must report the *effective* model (the saved
preference actually used at runtime), not only the .env configured default."""
from __future__ import annotations

import contextlib
import io
import unittest
from unittest.mock import patch

from secops_agent import main as main_mod


class DoctorDiagnosticsTests(unittest.TestCase):
    def test_doctor_reports_effective_model(self) -> None:
        with patch.object(
            main_mod, "_startup_model_selection", return_value=("gemma-4-31b-it", "high")
        ):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                main_mod.doctor()
        out = buf.getvalue()
        self.assertIn("Effective model", out)
        self.assertIn("gemma-4-31b-it", out)


if __name__ == "__main__":
    unittest.main()
