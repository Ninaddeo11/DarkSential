from __future__ import annotations

import math
import statistics
from datetime import UTC, datetime, timedelta

import pytest
from hypothesis import given
from hypothesis import strategies as st

from app.behavior.baseline import Baseline, choose
from app.behavior.config import load_behavior_config
from app.behavior.events import MqttInfo, TrafficEvent
from app.behavior.features import FEATURES, compute, topic_matches
from app.behavior.welford import Welford
from app.core.config import Settings

T0 = datetime(2026, 10, 1, tzinfo=UTC)
floats = st.floats(min_value=-1e6, max_value=1e6, allow_nan=False, allow_infinity=False)


# --- Welford -------------------------------------------------------------------------


@given(st.lists(floats, min_size=2, max_size=200))
def test_welford_matches_statistics(xs: list[float]) -> None:
    w = Welford()
    for x in xs:
        w.add(x)
    assert w.n == len(xs)
    assert w.mean == pytest.approx(statistics.fmean(xs), rel=1e-9, abs=1e-6)
    assert w.variance == pytest.approx(statistics.variance(xs), rel=1e-7, abs=1e-4)


@given(st.lists(floats, max_size=100), st.lists(floats, max_size=100))
def test_welford_merge_equals_sequential(a: list[float], b: list[float]) -> None:
    wa, wb, wall = Welford(), Welford(), Welford()
    for x in a:
        wa.add(x)
        wall.add(x)
    for x in b:
        wb.add(x)
        wall.add(x)
    merged = wa.merge(wb)
    assert merged.n == wall.n
    assert merged.mean == pytest.approx(wall.mean, rel=1e-9, abs=1e-6)
    assert merged.m2 == pytest.approx(wall.m2, rel=1e-6, abs=1e-3)


def test_welford_numerically_stable_with_large_offset() -> None:
    # Naive sum-of-squares loses all precision here; Welford doesn't.
    w = Welford()
    for x in (1e9 + 4, 1e9 + 7, 1e9 + 13, 1e9 + 16):
        w.add(x)
    assert w.variance == pytest.approx(30.0)


def test_welford_edge_cases() -> None:
    w = Welford()
    assert w.variance == 0.0
    assert w.std == 0.0
    w.add(5)
    assert w.variance == 0.0
    assert w.zscore(5, abs_floor=1.0) == 0.0
    assert w.zscore(8, abs_floor=1.0) == 3.0  # floored std
    assert Welford.from_dict(w.to_dict()) == w
    with pytest.raises(ValueError, match="finite"):
        w.add(math.nan)


def test_zscore_relative_floor() -> None:
    w = Welford()
    for _ in range(30):
        w.add(100.0)  # zero variance
    # rel_floor 0.1 * mean 100 = 10 -> a jump to 130 is z = 3, not infinity
    assert w.zscore(130, rel_floor=0.1, abs_floor=1.0) == pytest.approx(3.0)


# --- features ------------------------------------------------------------------------


def ev(sec: float, **kw: object) -> TrafficEvent:
    base: dict[str, object] = {
        "ts": T0 + timedelta(seconds=sec),
        "src_ip": "192.168.50.5",
        "proto": "tcp",
    }
    base.update(kw)
    return TrafficEvent(**base)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("pattern", "topic", "expected"),
    [
        ("dsn/cmd/#", "dsn/cmd/quarantine/all", True),
        ("dsn/cmd/#", "dsn/cmd", True),
        ("dsn/+/x", "dsn/a/x", True),
        ("dsn/+/x", "dsn/a/b/x", False),
        ("$SYS/#", "$SYS/broker/load", True),
        ("home/a", "home/a/b", False),
        ("home/a/b", "home/a", False),
    ],
)
def test_topic_matches(pattern: str, topic: str, expected: bool) -> None:
    assert topic_matches(pattern, topic) is expected


def test_compute_features() -> None:
    events = [
        ev(1, dst_ip="10.0.0.1", dst_port=22, proto="ssh", bytes=100, ok=False),
        ev(2, dst_ip="10.0.0.1", dst_port=22, proto="ssh", bytes=300, ok=False),
        ev(3, dst_ip="192.168.50.1", dst_port=53, proto="dns", bytes=60, dns_query="a.example"),
        ev(4, dst_port=8883, proto="mqtt", bytes=10, mqtt=MqttInfo(packet="CONNECT")),
        ev(5, dst_port=8883, proto="mqtt", mqtt=MqttInfo(packet="SUBSCRIBE", topic="home/#")),
        ev(6, dst_port=8883, proto="mqtt", mqtt=MqttInfo(packet="PUBLISH", topic="dsn/cmd/x")),
        ev(7, dst_port=8883, proto="mqtt", mqtt=MqttInfo(packet="PUBLISH", topic="home/t")),
    ]
    v, protos = compute(events, 30, ["dsn/cmd/#"], known_protocols={"mqtt"})
    assert set(v) == set(FEATURES)
    assert v["request_rate"] == 14  # 7 events / 30 s -> per minute
    assert v["unique_destinations"] == 3  # (10.0.0.1,22), (192.168.50.1,53), (None,8883)
    assert v["unique_dst_ports"] == 3
    assert v["failed_attempts"] == 2
    assert v["dns_rate"] == 2
    assert v["mqtt_connect_rate"] == 2
    assert v["mqtt_wildcard_subs"] == 1
    assert v["mqtt_restricted_publishes"] == 1
    assert v["new_protocols"] == 2  # ssh, dns not in known
    assert protos == {"ssh", "dns", "mqtt"}
    assert 0 < v["proto_entropy"] <= math.log2(3)
    assert v["bytes_var"] > 0


def test_compute_empty_and_unknown_baseline() -> None:
    v, protos = compute([], 60, [])
    assert v["request_rate"] == 0
    assert v["proto_entropy"] == 0
    assert protos == set()
    v2, _ = compute([ev(1, proto="ssh")], 60, [], known_protocols=None)
    assert v2["new_protocols"] == 0  # no mature baseline -> nothing is "new"


def test_traffic_event_validation() -> None:
    with pytest.raises(ValueError):  # noqa: PT011
        ev(1, proto="tcp; drop")
    with pytest.raises(ValueError):  # noqa: PT011
        ev(1, dst_port=70000)
    assert MqttInfo(packet="CONNECT", client_id="a\x1b[31mb").client_id == "ab"


# --- baselines -----------------------------------------------------------------------


def test_baseline_choose_cold_fleet_device(settings: Settings) -> None:
    cfg = load_behavior_config(settings.behavior_config_path).baseline
    device, fleet = Baseline(), Baseline()
    vector = {f: 1.0 for f in FEATURES}
    assert choose(device, fleet, vector, cfg).source == "none"
    for _ in range(cfg.fleet_min_windows):
        fleet.update(vector, {"mqtt"})
    view = choose(device, fleet, vector, cfg)
    assert view.source == "fleet"
    assert view.cold_start
    assert "new_protocols" not in view.zscores
    for _ in range(cfg.min_windows):
        device.update(vector, {"mqtt"})
    view = choose(device, fleet, vector, cfg)
    assert view.source == "device"
    assert not view.cold_start
    restored = Baseline.from_dict(device.to_dict())
    assert restored.windows == device.windows
    assert restored.protocols == {"mqtt"}
    assert restored.stats["request_rate"] == device.stats["request_rate"]


def test_behavior_config_validation(settings: Settings, tmp_path: object) -> None:
    from pathlib import Path

    from pydantic import ValidationError

    from app.behavior.config import BehaviorConfig

    cfg = load_behavior_config(settings.behavior_config_path)
    data = cfg.model_dump()
    data["anomaly"]["weights"] = {"zscore": 1.0}
    with pytest.raises(ValidationError, match="exactly zscore and iforest"):
        BehaviorConfig.model_validate(data)
    data["anomaly"]["weights"] = {"zscore": 0.0, "iforest": 0.0}
    with pytest.raises(ValidationError, match="not all zero"):
        BehaviorConfig.model_validate(data)
    assert isinstance(Path(str(tmp_path)), Path)
