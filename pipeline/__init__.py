"""AreWeCooked? data pipeline.

Stages:
    1. ``fetch.py``  downloads public raw data into ``data/raw/`` (gitignored).
    2. ``build.py``  turns raw data into clean CSV tables in ``data/clean/`` and
       exports the compact JSON bundle the site reads from ``site/public/data/``.
"""

__version__ = "1.0.0"
