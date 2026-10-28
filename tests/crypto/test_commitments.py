"""Typed-path leaf commitments, payload roots, redaction stability and leaf-set structure."""

import hashlib
from collections.abc import Callable, Iterator

import pytest

from aip.crypto.canonical import MAX_DEPTH, JsonValue, canonical_json
from aip.crypto.commitments import (
    Leaf,
    LeafStatus,
    TypedPath,
    build_leaves,
    check_leaf,
    commit_leaf,
    flatten_payload,
    payload_root,
    unflatten,
    validate_leaf_set,
)
from aip.crypto.errors import LeafError
from tests.crypto import vectors as kat


def fixed_salts() -> Callable[[], bytes]:
    counter: Iterator[int] = iter(range(256))
    return lambda: kat.salt(next(counter))


def root_of(payload: dict[str, JsonValue]) -> str:
    return payload_root(build_leaves(payload, salt_factory=fixed_salts()))


# --- Known-answer vectors -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("path", "value", "salt_index", "preimage", "digest"),
    kat.LEAF_VECTORS,
    ids=[str(v[0]) for v in kat.LEAF_VECTORS],
)
def test_leaf_vectors(
    path: TypedPath, value: JsonValue, salt_index: int, preimage: bytes, digest: str
) -> None:
    assert (
        canonical_json(["aip-leaf-v1", list(path), kat.salt(salt_index).hex(), value]) == preimage
    )
    assert hashlib.sha256(preimage).hexdigest() == digest
    assert commit_leaf(path, kat.salt(salt_index), value) == digest


def test_build_leaves_and_payload_root_vector() -> None:
    leaves = build_leaves(kat.PAYLOAD, salt_factory=fixed_salts())
    assert [(leaf.path, leaf.commitment) for leaf in leaves] == [
        (v[0], v[4]) for v in kat.LEAF_VECTORS
    ]
    assert hashlib.sha256(kat.PAYLOAD_ROOT_BYTES).hexdigest() == kat.PAYLOAD_ROOT
    assert payload_root(leaves) == kat.PAYLOAD_ROOT


def test_typed_path_regression_vectors() -> None:
    """{"a": ["x"]} and {"a": {"0": "x"}} were indistinguishable with JSON Pointer paths."""
    assert hashlib.sha256(kat.TYPED_ARRAY_LEAF_BYTES).hexdigest() == kat.TYPED_ARRAY_LEAF
    assert hashlib.sha256(kat.TYPED_OBJECT_LEAF_BYTES).hexdigest() == kat.TYPED_OBJECT_LEAF
    assert root_of({"a": ["x"]}) == kat.TYPED_ARRAY_ROOT
    assert root_of({"a": {"0": "x"}}) == kat.TYPED_OBJECT_ROOT
    assert kat.TYPED_ARRAY_ROOT != kat.TYPED_OBJECT_ROOT


# --- Structure binding ----------------------------------------------------------------------


def test_flatten_uses_typed_paths() -> None:
    assert flatten_payload({"a": ["x"]}) == [(("a", 0), "x")]
    assert flatten_payload({"a": {"0": "x"}}) == [(("a", "0"), "x")]
    assert flatten_payload({}) == [((), {})]
    assert flatten_payload({"a": {"b": {"c": []}}}) == [(("a", "b", "c"), [])]


@pytest.mark.parametrize(
    ("left", "right"),
    [
        ({"a": ["x"]}, {"a": {"0": "x"}}),
        ({"a": ["x", "y"]}, {"a": {"0": "x", "1": "y"}}),
        ({"a": {}}, {"a": []}),
        ({"a": [{}]}, {"a": [[]]}),
        ({"a": {"b": {}}}, {"a": {"b": []}}),
        ({"a": [[]]}, {"a": []}),
        ({"a": None}, {"a": {}}),
        ({"a": [None]}, {"a": []}),
        ({"a": "x"}, {"a": ["x"]}),
        ({"a": 1}, {"a": "1"}),
        ({"a": True}, {"a": 1}),
        ({"a": ["x", "y"]}, {"a": ["y", "x"]}),
        ({"a": {"b": "x"}}, {"a/b": "x"}),
        ({}, {"a": {}}),
    ],
)
def test_distinct_structures_have_distinct_roots(
    left: dict[str, JsonValue], right: dict[str, JsonValue]
) -> None:
    assert root_of(left) != root_of(right)


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"a": {}},
        {"a": []},
        {"a": [{}, [], [[]], {"b": []}]},
        {"0": "x", "1": ["y", {"2": None}]},
        {"caf\u00e9": "\u20ac", "\U0001f600": [True, False, None, 0, -1]},
        {"a/b": {"~": "x"}},
        kat.PAYLOAD,
    ],
)
def test_unflatten_round_trip(payload: dict[str, JsonValue]) -> None:
    assert unflatten(build_leaves(payload)) == payload


# --- Malformed leaf sets ---------------------------------------------------------------------


def _leaf(path: TypedPath, value: JsonValue = "x") -> Leaf:
    return Leaf(path, commit_leaf(path, kat.salt(0), value), kat.salt(0), value)


@pytest.mark.parametrize(
    ("leaves", "message"),
    [
        ([], "at least one leaf"),
        ([_leaf(("a",)), _leaf(("a",))], "duplicate"),
        ([_leaf(("a",)), _leaf(("a", "b"))], "container"),
        ([_leaf(("a", 0)), _leaf(("a", "b"))], "mixed"),
        ([_leaf(("a", 0)), _leaf(("a", 2))], "0..n-1"),
        ([_leaf(("a", 1))], "0..n-1"),
        ([_leaf((0,))], "root must be an object"),
        ([_leaf((), {}), _leaf(("a",))], "root leaf"),
    ],
)
def test_malformed_leaf_sets_rejected(leaves: list[Leaf], message: str) -> None:
    with pytest.raises(LeafError, match=message):
        validate_leaf_set(leaves)
    with pytest.raises(LeafError):
        payload_root(leaves)
    with pytest.raises(LeafError):
        unflatten(leaves)


def test_non_leaf_items_rejected() -> None:
    with pytest.raises(LeafError, match="expected Leaf"):
        validate_leaf_set([("a",)])  # type: ignore[list-item]


def test_root_leaf_for_the_empty_payload() -> None:
    root = Leaf((), commit_leaf((), kat.salt(0), {}), kat.salt(0), {})
    assert validate_leaf_set([root]) == [root]
    assert check_leaf(root) is LeafStatus.VALID
    assert payload_root([root]) == root_of({})
    assert unflatten([root]) == {}
    assert [leaf.path for leaf in build_leaves({})] == [()]


@pytest.mark.parametrize("value", [[], "x", None, 0, True], ids=repr)
def test_root_leaf_rejects_anything_but_the_empty_object(value: JsonValue) -> None:
    with pytest.raises(LeafError, match=r"empty object \{\}"):
        commit_leaf((), kat.salt(0), value)
    with pytest.raises(LeafError, match=r"empty object \{\}"):
        Leaf((), "0" * 64, kat.salt(0), value)


def test_root_leaf_cannot_be_redacted() -> None:
    root = build_leaves({})[0]
    with pytest.raises(LeafError, match="cannot be redacted"):
        root.redacted()
    with pytest.raises(LeafError, match="cannot be redacted"):
        Leaf((), root.commitment)


@pytest.mark.parametrize(
    "build",
    [
        lambda: Leaf(("a",), "A" * 64),
        lambda: Leaf(("a",), "0" * 63),
        lambda: Leaf(("a",), "g" * 64),
        lambda: Leaf(("a",), "0" * 64, b"short", "x"),
        lambda: Leaf(("a",), "0" * 64, bytearray(32), "x"),  # type: ignore[arg-type]
        lambda: Leaf(("a",), "0" * 64, None, "value-without-salt"),
        lambda: Leaf(("a",), "0" * 64, kat.salt(0), {"non": "empty"}),
        lambda: Leaf(("a",), "0" * 64, kat.salt(0), 1.5),  # type: ignore[arg-type]
        lambda: Leaf(["a"], "0" * 64),  # type: ignore[arg-type]
        lambda: Leaf((True,), "0" * 64),
        lambda: Leaf((-1,), "0" * 64),
        lambda: Leaf(("e\u0301",), "0" * 64),
        lambda: Leaf(("a",) * (MAX_DEPTH + 1), "0" * 64),
    ],
)
def test_invalid_leaf_construction(build: Callable[[], Leaf]) -> None:
    with pytest.raises(LeafError):
        build()


# --- Depth limits ----------------------------------------------------------------------------


def _deep_payload(depth: int, leaf: JsonValue) -> dict[str, JsonValue]:
    """A payload whose total depth is ``depth`` containers, ending in ``leaf``."""
    value: JsonValue = leaf
    for _ in range(depth - 1):
        value = {"k": value}
    return {"k": value} if depth >= 1 else {}


def test_depth_limit_is_consistent_for_flatten_and_unflatten() -> None:
    at_limit = _deep_payload(MAX_DEPTH, "x")
    leaves = build_leaves(at_limit)
    assert len(leaves[0].path) == MAX_DEPTH
    assert unflatten(leaves) == at_limit
    with pytest.raises(LeafError, match="MAX_DEPTH"):
        build_leaves(_deep_payload(MAX_DEPTH + 1, "x"))
    with pytest.raises(LeafError, match="MAX_DEPTH"):
        build_leaves(_deep_payload(MAX_DEPTH, {}))


def test_empty_container_leaf_depth() -> None:
    commit_leaf(("k",) * (MAX_DEPTH - 1), kat.salt(0), {})
    with pytest.raises(LeafError, match="MAX_DEPTH"):
        commit_leaf(("k",) * MAX_DEPTH, kat.salt(0), {})
    commit_leaf(("k",) * MAX_DEPTH, kat.salt(0), "scalar")


# --- Leaf status and redaction ---------------------------------------------------------------


def test_check_leaf_statuses() -> None:
    leaf = build_leaves({"a": "secret"})[0]
    assert check_leaf(leaf) is LeafStatus.VALID
    assert check_leaf(Leaf(leaf.path, leaf.commitment, leaf.salt, "changed")) is LeafStatus.INVALID
    assert check_leaf(Leaf(leaf.path, leaf.commitment, kat.salt(9), "secret")) is LeafStatus.INVALID
    assert check_leaf(Leaf(("b",), leaf.commitment, leaf.salt, "secret")) is LeafStatus.INVALID
    redacted = leaf.redacted()
    assert check_leaf(redacted) is LeafStatus.REDACTED_UNVERIFIED
    assert check_leaf(redacted) is not LeafStatus.VALID


def test_swapped_leaf_values_fail() -> None:
    a, b = build_leaves({"a": "one", "b": "two"})
    swapped_a = Leaf(a.path, a.commitment, b.salt, b.value)
    assert check_leaf(swapped_a) is LeafStatus.INVALID


def test_redaction_keeps_payload_root() -> None:
    leaves = build_leaves(kat.PAYLOAD, salt_factory=fixed_salts())
    partly = [leaf.redacted() if leaf.path == ("account", "number") else leaf for leaf in leaves]
    fully = [leaf.redacted() for leaf in leaves]
    assert payload_root(partly) == kat.PAYLOAD_ROOT
    assert payload_root(fully) == kat.PAYLOAD_ROOT
    statuses = {leaf.path: check_leaf(leaf) for leaf in partly}
    assert statuses.pop(("account", "number")) is LeafStatus.REDACTED_UNVERIFIED
    assert set(statuses.values()) == {LeafStatus.VALID}
    with pytest.raises(LeafError, match="redacted"):
        unflatten(partly)


def test_value_change_keeps_root_but_fails_leaf_check() -> None:
    """payload_root alone does not verify revealed contents: it never reads values (DESIGN C5)."""
    leaves = build_leaves(kat.PAYLOAD, salt_factory=fixed_salts())
    target = leaves[0]
    assert target.path == ("account", "number")
    tampered = Leaf(target.path, target.commitment, target.salt, "900999999")
    leaves[0] = tampered
    assert payload_root(leaves) == kat.PAYLOAD_ROOT  # root unchanged: tampering invisible here
    assert check_leaf(tampered) is LeafStatus.INVALID  # caught only by the per-leaf check


def test_changed_commitment_changes_root() -> None:
    leaves = build_leaves(kat.PAYLOAD, salt_factory=fixed_salts())
    leaves[0] = Leaf(leaves[0].path, "0" * 64)
    assert payload_root(leaves) != kat.PAYLOAD_ROOT


def test_leaf_repr_hides_value_and_salt() -> None:
    leaf = build_leaves({"ssn": "900123456"})[0]
    assert "900123456" not in repr(leaf)
    assert leaf.salt is not None
    assert leaf.salt.hex() not in repr(leaf)


def test_default_salts_are_random_and_32_bytes() -> None:
    first, second = build_leaves({"a": "x"})[0], build_leaves({"a": "x"})[0]
    assert first.salt is not None
    assert second.salt is not None
    assert len(first.salt) == 32
    assert first.salt != second.salt
    assert first.commitment != second.commitment


def test_flatten_rejects_non_object_payloads() -> None:
    non_objects: list[object] = [[], "x", None, 1]
    for payload in non_objects:
        with pytest.raises(LeafError, match="JSON object"):
            flatten_payload(payload)
    with pytest.raises(LeafError):
        flatten_payload({"a": 1.5})
