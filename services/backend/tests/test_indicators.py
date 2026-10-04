import copy, json
import pytest
from tracehawk.core import ROOT
from tracehawk.detections import canonical_indicators


def test_canonical_and_duplicate_indicators():
    body = json.loads((ROOT / "contracts/examples/phase2-indicators.json").read_text())
    body["entries"] = [
        {
            "kind": "domain",
            "value": "HOST0.EXAMPLE.TEST.",
            "description": "case/root normalization",
        },
        {
            "kind": "ip",
            "value": "2001:0DB8:0:0:0:0:0:1",
            "description": "IPv6 normalization",
        },
    ]
    result = canonical_indicators(body)
    assert result["entries"][0]["value"] == "host0.example.test"
    assert result["entries"][1]["value"] == "2001:db8::1"
    duplicate = copy.deepcopy(result)
    duplicate["entries"].append(
        {
            "kind": "domain",
            "value": "HOST0.EXAMPLE.TEST.",
            "description": "same exact indicator",
        }
    )
    with pytest.raises(ValueError):
        canonical_indicators(duplicate)


@pytest.mark.parametrize(
    "kind,value",
    [
        ("ip", "not-an-ip"),
        ("domain", "a..test"),
        ("domain", "*.example.test"),
        ("domain", "-invalid.test"),
        ("domain", "a test"),
    ],
)
def test_invalid_indicators(kind, value):
    body = json.loads((ROOT / "contracts/examples/phase2-indicators.json").read_text())
    body["entries"] = [{"kind": kind, "value": value, "description": "invalid entry"}]
    with pytest.raises(ValueError):
        canonical_indicators(body)
