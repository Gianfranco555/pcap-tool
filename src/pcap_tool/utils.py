from __future__ import annotations

import pandas as pd


def export_to_csv(data_to_export: pd.DataFrame, filename: str) -> None:
    """Write ``data_to_export`` to ``filename`` as CSV without index."""
    data_to_export.to_csv(filename, index=False)
