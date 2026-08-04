# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: MIT
import pytest

def pytest_addoption(parser):
    parser.addoption(
        "--trace-path",
        required=True,
        help="Path to converted CTF trace (with UST)"
    )
