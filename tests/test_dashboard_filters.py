"""Independent risk axes and observations filter CSV but not inventory metrics."""
import csv
import io
from unittest.mock import MagicMock, patch

import pytest

import dashboard


def inventory():
    def component(name, quantum, classical, observation):
        return {"name": name, "properties": [
            {"name": "cryptotrace:riskRating", "value": quantum},
            {"name": "cryptotrace:classical_risk", "value": classical},
            {"name": "cryptotrace:observation", "value": observation},
            {"name": "cryptotrace:sourceType", "value": "network-capture"},
        ]}
    return {"components": [
        component("Cleartext", "unknown", "critical", "observed"),
        component("RSA-offered", "critical", "unknown", "advertised"),
        component("RSA-selected", "critical", "unknown", "negotiated"),
        component("AES", "safe", "safe", "negotiated"),
    ]}


@pytest.mark.parametrize("selections,expected", [
    ({}, {"Cleartext", "RSA-offered", "RSA-selected", "AES"}),
    ({"Classical risk": ["Critical"]}, {"Cleartext"}),
    ({"Quantum risk": ["Critical"], "Observation": ["negotiated"]}, {"RSA-selected"}),
])
def test_filter_and_export_preserve_full_inventory_metrics(selections, expected):
    with patch("dashboard.st") as st, patch("dashboard._render_metrics") as metrics:
        st.session_state = {}
        st.multiselect.side_effect = lambda label, options, default: selections.get(label, default)
        st.text_input.return_value = ""
        st.button.return_value = False
        st.columns.side_effect = lambda spec: [MagicMock() for _ in range(spec if isinstance(spec, int) else len(spec))]
        dashboard.render_dashboard(inventory())
        full_df = metrics.call_args.args[0]
        summary = metrics.call_args.kwargs["summary"]
        assert len(full_df) == summary["counts"]["Total"] == 4
        assert summary["classical_counts"]["Critical"] == 1
        exports = [call.kwargs for call in st.download_button.call_args_list if call.kwargs.get("mime") == "text/csv"]
        assert len(exports) == 1
        data = exports[0]["data"]
        if isinstance(data, bytes):
            data = data.decode("utf-8")
        rows = list(csv.DictReader(io.StringIO(data)))
        assert "Quantum Risk" in rows[0]
        assert "Classical Risk" in rows[0]
        assert "Risk Rating" not in rows[0]
        assert {row["Algorithm"] for row in rows} == expected
