"""The native OpenAPI document (Swagger UI at /docs) declares API-key auth and the POST bodies."""

from typing import Any

import pytest
from fastapi.testclient import TestClient

from aip.api.schemas import RedactionRequest, RetentionRequest
from aip.ingest import EventInput
from tests.api.conftest import auth


@pytest.fixture
def spec(api: TestClient) -> dict[str, Any]:
    document: dict[str, Any] = api.get("/openapi.json").json()
    return document


def test_api_key_security_scheme_is_declared(spec: dict[str, Any]) -> None:
    assert spec["components"]["securitySchemes"]["ApiKey"] == {
        "type": "apiKey",
        "in": "header",
        "name": "X-API-Key",
        "description": (
            "API key for the writer, auditor or admin role (python -m aip.cli new-api-key)."
        ),
    }


def test_every_audit_operation_requires_the_api_key(spec: dict[str, Any]) -> None:
    operations = [
        (path, method, operation)
        for path, methods in spec["paths"].items()
        if path.startswith("/audit")
        for method, operation in methods.items()
    ]
    assert len(operations) == 9
    for path, method, operation in operations:
        assert operation.get("security") == [{"ApiKey": []}], (path, method)


@pytest.mark.parametrize(
    ("path", "model", "required"),
    [
        ("/audit/events", EventInput, True),
        ("/audit/events/{event_id}/redactions", RedactionRequest, True),
        ("/audit/retention/runs", RetentionRequest, False),
    ],
)
def test_post_bodies_are_documented_from_the_validating_models(
    spec: dict[str, Any], path: str, model: Any, required: bool
) -> None:
    body = spec["paths"][path]["post"]["requestBody"]
    assert body["required"] is required
    content = body["content"]["application/json"]
    assert _without_null_defaults(content["schema"]) == _without_null_defaults(
        model.model_json_schema(by_alias=True)
    )
    model.model_validate(content["example"])  # the documented example is itself valid


def _without_null_defaults(value: Any) -> Any:
    """FastAPI drops ``"default": null`` when it writes the OpenAPI document; ignore only that."""
    if isinstance(value, dict):
        return {
            key: _without_null_defaults(item)
            for key, item in value.items()
            if not (key == "default" and item is None)
        }
    if isinstance(value, list):
        return [_without_null_defaults(item) for item in value]
    return value


def test_event_body_schema_matches_the_specification_fields(spec: dict[str, Any]) -> None:
    schema = spec["paths"]["/audit/events"]["post"]["requestBody"]["content"]["application/json"][
        "schema"
    ]
    assert set(schema["properties"]) == {
        "eventType",
        "actorId",
        "resourceType",
        "resourceId",
        "payload",
        "timestamp",
    }
    assert set(schema["required"]) == {
        "eventType",
        "actorId",
        "resourceType",
        "resourceId",
        "payload",
    }
    assert schema["additionalProperties"] is False


def test_documented_example_is_accepted_by_the_live_endpoint(
    api: TestClient, spec: dict[str, Any]
) -> None:
    example = spec["paths"]["/audit/events"]["post"]["requestBody"]["content"]["application/json"][
        "example"
    ]
    response = api.post("/audit/events", json=example, headers=auth("writer"))
    assert response.status_code == 201


def test_declaring_the_scheme_does_not_change_auth_responses(api: TestClient) -> None:
    """Swagger's scheme is documentation only: missing key 401, wrong role 403, both RFC 9457."""
    missing = api.get("/audit/events")
    wrong_role = api.get("/audit/events", headers=auth("writer"))
    bad_key = api.get("/audit/events", headers={"X-API-Key": "not-a-configured-key"})
    assert (missing.status_code, missing.json()["code"]) == (401, "unauthorized")
    assert (bad_key.status_code, bad_key.json()["code"]) == (401, "unauthorized")
    assert (wrong_role.status_code, wrong_role.json()["code"]) == (403, "forbidden")
    assert missing.headers["content-type"] == "application/problem+json"
