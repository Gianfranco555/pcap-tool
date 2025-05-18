import pandas as pd
import yaml
from pathlib import Path
from heuristics.engine import HeuristicEngine


def build_engine(rule, tmp_path):
    rules = {
        "target_column_map": {"rules": "result"},
        "default_values": {"result": "DEFAULT"},
        "rules": [rule],
    }
    path = tmp_path / "rules.yaml"
    path.write_text(yaml.safe_dump(rules))
    return HeuristicEngine(str(path))


def test_equals_operator(tmp_path):
    rule = {
        "name": "eq",
        "conditions": [{"field": "protocol", "operator": "equals", "value": "TCP"}],
        "output_value": "MATCH",
    }
    engine = build_engine(rule, tmp_path)
    df = pd.DataFrame([{"protocol": "TCP"}, {"protocol": "UDP"}])
    result = engine.tag_flows(df)
    assert list(result["result"]) == ["MATCH", "DEFAULT"]


def test_not_equals_operator(tmp_path):
    rule = {
        "name": "neq",
        "conditions": [
            {"field": "protocol", "operator": "not_equals", "value": "TCP"},
            {"field": "protocol", "operator": "exists"},
        ],
        "output_value": "NOT_TCP",
    }
    engine = build_engine(rule, tmp_path)
    df = pd.DataFrame([{"protocol": "TCP"}, {"protocol": "UDP"}])
    result = engine.tag_flows(df)
    assert list(result["result"]) == ["DEFAULT", "NOT_TCP"]


def test_in_not_in_operator(tmp_path):
    rule_in = {
        "name": "in",
        "conditions": [
            {"field": "destination_port", "operator": "in", "value": [80, 443]},
            {"field": "destination_port", "operator": "exists"},
        ],
        "output_value": "WEB",
    }
    engine = build_engine(rule_in, tmp_path)
    df = pd.DataFrame([{"destination_port": 80}, {"destination_port": 22}])
    result = engine.tag_flows(df)
    assert list(result["result"]) == ["WEB", "DEFAULT"]

    rule_not_in = {
        "name": "notin",
        "conditions": [
            {"field": "destination_port", "operator": "not_in", "value": [80, 443]},
            {"field": "destination_port", "operator": "exists"},
        ],
        "output_value": "NON_WEB",
    }
    engine = build_engine(rule_not_in, tmp_path)
    result = engine.tag_flows(df)
    assert list(result["result"]) == ["DEFAULT", "NON_WEB"]


def test_regex_and_format(tmp_path):
    rule = {
        "name": "regex",
        "conditions": [
            {"field": "host", "operator": "regex", "value": "(?i)example"},
            {"field": "host", "operator": "exists"},
        ],
        "output_value_format": "HOST_{host}",
    }
    engine = build_engine(rule, tmp_path)
    df = pd.DataFrame([{"host": "example.com"}, {"host": "other"}])
    result = engine.tag_flows(df)
    assert list(result["result"]) == ["HOST_example.com", "DEFAULT"]


def test_cidr_operator(tmp_path):
    rule = {
        "name": "cidr",
        "conditions": [{"field": "source_ip", "operator": "cidr", "value": "192.168.0.0/16"}],
        "output_value": "LOCAL",
    }
    engine = build_engine(rule, tmp_path)
    df = pd.DataFrame([{"source_ip": "192.168.1.5"}, {"source_ip": "8.8.8.8"}])
    result = engine.tag_flows(df)
    assert list(result["result"]) == ["LOCAL", "DEFAULT"]


def test_exists_not_exists(tmp_path):
    rule_exists = {
        "name": "exists",
        "conditions": [{"field": "host", "operator": "exists"}],
        "output_value": "HAS_HOST",
    }
    engine = build_engine(rule_exists, tmp_path)
    df = pd.DataFrame([{"host": "yes"}, {"host": None}])
    result = engine.tag_flows(df)
    assert list(result["result"]) == ["HAS_HOST", "DEFAULT"]

    rule_not = {
        "name": "notexists",
        "conditions": [{"field": "host", "operator": "not_exists"}],
        "output_value": "NO_HOST",
    }
    engine = build_engine(rule_not, tmp_path)
    result = engine.tag_flows(df)
    assert list(result["result"]) == ["DEFAULT", "NO_HOST"]


def test_comparisons(tmp_path):
    rule_gt = {
        "name": "gt",
        "conditions": [{"field": "size", "operator": "gt", "value": 100}],
        "output_value": "BIG",
    }
    engine = build_engine(rule_gt, tmp_path)
    df = pd.DataFrame([{"size": 150}, {"size": 10}])
    result = engine.tag_flows(df)
    assert list(result["result"]) == ["BIG", "DEFAULT"]

    rule_lt = {
        "name": "lt",
        "conditions": [{"field": "size", "operator": "lt", "value": 50}],
        "output_value": "SMALL",
    }
    engine = build_engine(rule_lt, tmp_path)
    result = engine.tag_flows(df)
    assert list(result["result"]) == ["DEFAULT", "SMALL"]


def test_starts_and_ends(tmp_path):
    rule_start = {
        "name": "start",
        "conditions": [{"field": "host", "operator": "starts_with", "value": "pre"}],
        "output_value": "PREFIX",
    }
    engine = build_engine(rule_start, tmp_path)
    df = pd.DataFrame([{"host": "prefix"}, {"host": "xprefix"}])
    result = engine.tag_flows(df)
    assert list(result["result"]) == ["PREFIX", "DEFAULT"]

    rule_end = {
        "name": "end",
        "conditions": [{"field": "host", "operator": "ends_with", "value": ".net"}],
        "output_value": "NET",
    }
    engine = build_engine(rule_end, tmp_path)
    df = pd.DataFrame([{"host": "site.net"}, {"host": "site.com"}])
    result = engine.tag_flows(df)
    assert list(result["result"]) == ["NET", "DEFAULT"]


def test_stop_processing(tmp_path):
    rules = {
        "target_column_map": {"rules": "result"},
        "default_values": {"result": "DEFAULT"},
        "rules": [
            {
                "name": "first",
                "conditions": [{"field": "protocol", "operator": "equals", "value": "TCP"}],
                "output_value": "FIRST",
                "stop_processing": True,
            },
            {
                "name": "second",
                "conditions": [{"field": "protocol", "operator": "equals", "value": "TCP"}],
                "output_value": "SECOND",
            },
        ],
    }
    path = tmp_path / "rules.yaml"
    path.write_text(yaml.safe_dump(rules))
    engine = HeuristicEngine(str(path))
    df = pd.DataFrame([{"protocol": "TCP"}])
    result = engine.tag_flows(df)
    assert result["result"].iloc[0] == "FIRST"
