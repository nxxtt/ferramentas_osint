import argparse
import json

import pytest

from openapidiscovery import (
    DEFAULT_PATHS,
    ApiSpecInfo,
    EndpointInfo,
    _load_paths_from_args,
    _parse_openapi_v2,
    _parse_openapi_v3,
    build_parser,
    parse_spec,
)


class TestEndpointInfo:
    def test_frozen(self):
        ep = EndpointInfo(method="GET", path="/users")
        with pytest.raises(AttributeError):
            ep.method = "POST"

    def test_defaults(self):
        ep = EndpointInfo(method="GET", path="/users")
        assert ep.summary == ""
        assert ep.tags == []
        assert ep.parameters == []

    def test_all_fields(self):
        ep = EndpointInfo(
            method="POST",
            path="/users",
            summary="Create user",
            tags=["admin"],
            parameters=["name (query)"],
        )
        assert ep.method == "POST"
        assert ep.summary == "Create user"
        assert len(ep.tags) == 1
        assert len(ep.parameters) == 1


class TestApiSpecInfo:
    def test_frozen(self):
        spec = ApiSpecInfo(url="http://x.com/o.json", format="json")
        with pytest.raises(AttributeError):
            spec.title = "nope"

    def test_defaults(self):
        spec = ApiSpecInfo(url="http://x.com/o.json", format="json")
        assert spec.title == ""
        assert spec.version == ""
        assert spec.description == ""
        assert spec.servers == []
        assert spec.endpoints == []
        assert spec.schemas == []
        assert spec.raw_size == 0
        assert spec.status == 0

    def test_all_fields(self):
        spec = ApiSpecInfo(
            url="http://x.com/o.json",
            format="json",
            title="My API",
            version="1.0",
            description="Test",
            servers=["http://localhost"],
            endpoints=[EndpointInfo(method="GET", path="/a")],
            schemas=["User"],
            raw_size=512,
            status=200,
        )
        assert spec.title == "My API"
        assert len(spec.endpoints) == 1
        assert spec.raw_size == 512


class TestParseOpenapiV3:
    def test_basic_v3(self):
        spec = {
            "openapi": "3.0.0",
            "info": {"title": "Test API", "version": "1.0.0"},
            "servers": [{"url": "http://localhost:8080"}],
            "paths": {
                "/users": {
                    "get": {"summary": "List users", "tags": ["users"]},
                    "post": {"summary": "Create user", "tags": ["users"]},
                },
                "/health": {
                    "get": {"summary": "Health check"},
                },
            },
            "components": {
                "schemas": {"User": {"type": "object"}, "Error": {"type": "object"}},
            },
        }
        title, version, _desc, servers, endpoints, schemas = _parse_openapi_v3(spec)
        assert title == "Test API"
        assert version == "1.0.0"
        assert len(servers) == 1
        assert len(endpoints) == 3
        assert len(schemas) == 2
        assert endpoints[0].method == "GET"
        assert endpoints[0].path == "/users"
        assert endpoints[1].method == "POST"

    def test_empty_v3(self):
        title, version, _desc, servers, endpoints, schemas = _parse_openapi_v3({})
        assert title == ""
        assert version == ""
        assert servers == []
        assert endpoints == []
        assert schemas == []

    def test_with_parameters(self):
        spec = {
            "paths": {
                "/items": {
                    "get": {
                        "summary": "List items",
                        "tags": ["items"],
                        "parameters": [
                            {"name": "page", "in": "query"},
                            {"name": "id", "in": "path"},
                        ],
                    }
                }
            }
        }
        _, _, _, _, endpoints, _ = _parse_openapi_v3(spec)
        assert len(endpoints) == 1
        assert len(endpoints[0].parameters) == 2
        assert endpoints[0].parameters[0] == "page (query)"

    def test_non_dict_methods(self):
        spec = {"paths": {"/x": "not a dict"}}
        _, _, _, _, endpoints, _ = _parse_openapi_v3(spec)
        assert endpoints == []


class TestParseOpenapiV2:
    def test_basic_v2(self):
        spec = {
            "swagger": "2.0",
            "info": {"title": "Swagger 2", "version": "2.0"},
            "host": "api.example.com",
            "basePath": "/v1",
            "schemes": ["https"],
            "paths": {
                "/pets": {
                    "get": {"summary": "List pets"},
                },
            },
            "definitions": {"Pet": {"type": "object"}},
        }
        title, version, _desc, servers, endpoints, schemas = _parse_openapi_v2(spec)
        assert title == "Swagger 2"
        assert version == "2.0"
        assert len(servers) == 1
        assert "https://api.example.com/v1" in servers[0]
        assert len(endpoints) == 1
        assert len(schemas) == 1

    def test_empty_v2(self):
        title, _version, _desc, _servers, endpoints, schemas = _parse_openapi_v2({})
        assert title == ""
        assert endpoints == []
        assert schemas == []


class TestParseSpec:
    def test_valid_openapi3_json(self):
        data = json.dumps({
            "openapi": "3.0.0",
            "info": {"title": "Test", "version": "1.0"},
            "paths": {},
        }).encode()
        result = parse_spec(data, "application/json")
        assert result is not None
        assert result.format == "json"
        assert result.title == "Test"

    def test_valid_swagger2_json(self):
        data = json.dumps({
            "swagger": "2.0",
            "info": {"title": "S2", "version": "2.0"},
            "paths": {},
        }).encode()
        result = parse_spec(data, "application/json")
        assert result is not None
        assert result.format == "json"

    def test_valid_yaml(self):
        data = b"openapi: '3.0.0'\ninfo:\n  title: YAML API\n  version: '1.0'\npaths: {}"
        result = parse_spec(data, "application/x-yaml")
        assert result is not None
        assert result.format == "yaml"
        assert result.title == "YAML API"

    def test_invalid_content(self):
        assert parse_spec(b"not json or yaml", "text/html") is None

    def test_empty_content(self):
        assert parse_spec(b"", "application/json") is None

    def test_not_openapi(self):
        data = json.dumps({"random": "object"}).encode()
        assert parse_spec(data, "application/json") is None

    def test_guesses_json_from_content(self):
        data = json.dumps({"openapi": "3.0.0", "info": {"title": "Guess", "version": "1"}, "paths": {}}).encode()
        result = parse_spec(data, "text/plain")
        assert result is not None
        assert result.title == "Guess"

    def test_description_truncated(self):
        data = json.dumps({
            "openapi": "3.0.0",
            "info": {"title": "X", "version": "1", "description": "x" * 500},
            "paths": {},
        }).encode()
        result = parse_spec(data, "application/json")
        assert result is not None
        assert len(result.description) == 200


class TestDefaultPaths:
    def test_paths_are_strings(self):
        assert all(isinstance(p, str) for p in DEFAULT_PATHS)

    def test_common_swagger_paths(self):
        assert "swagger.json" in DEFAULT_PATHS
        assert "openapi.json" in DEFAULT_PATHS
        assert "openapi.yaml" in DEFAULT_PATHS
        assert "api-docs" in DEFAULT_PATHS
        assert "swagger-ui.html" in DEFAULT_PATHS

    def test_minimum_count(self):
        assert len(DEFAULT_PATHS) >= 15


class TestLoadPaths:
    def test_default(self):
        args = argparse.Namespace(paths=0)
        result = _load_paths_from_args(args)
        assert result == DEFAULT_PATHS

    def test_limited(self):
        args = argparse.Namespace(paths=5)
        result = _load_paths_from_args(args)
        assert len(result) == 5

    def test_zero_means_all(self):
        args = argparse.Namespace(paths=0)
        result = _load_paths_from_args(args)
        assert len(result) == len(DEFAULT_PATHS)


class TestBuildParser:
    def test_has_url(self):
        parser = build_parser()
        args = parser.parse_args(["http://example.com"])
        assert args.url == "http://example.com"

    def test_has_list(self):
        parser = build_parser()
        args = parser.parse_args(["-l", "urls.txt"])
        assert args.target_list == "urls.txt"

    def test_has_concurrency(self):
        parser = build_parser()
        args = parser.parse_args(["--concurrency", "50"])
        assert args.concurrency == 50

    def test_default_concurrency(self):
        parser = build_parser()
        args = parser.parse_args(["http://x.com"])
        assert args.concurrency == 30

    def test_has_endpoints_flag(self):
        parser = build_parser()
        args = parser.parse_args(["--endpoints", "http://x.com"])
        assert args.show_endpoints is True

    def test_has_paths_arg(self):
        parser = build_parser()
        args = parser.parse_args(["--paths", "10", "http://x.com"])
        assert args.paths == 10

    def test_has_timeout(self):
        parser = build_parser()
        args = parser.parse_args(["-t", "15", "http://x.com"])
        assert args.timeout == 15

    def test_has_output(self):
        parser = build_parser()
        args = parser.parse_args(["-o", "out.json", "http://x.com"])
        assert args.output == "out.json"

    def test_has_proxy(self):
        parser = build_parser()
        args = parser.parse_args(["--proxy", "http://p:8080", "http://x.com"])
        assert args.proxy == "http://p:8080"

    def test_has_user_agent(self):
        parser = build_parser()
        args = parser.parse_args(["-A", "Bot/1.0", "http://x.com"])
        assert args.user_agent == "Bot/1.0"

    def test_has_dry_run(self):
        parser = build_parser()
        args = parser.parse_args(["--dry-run", "http://x.com"])
        assert args.dry_run is True

    def test_has_retries(self):
        parser = build_parser()
        args = parser.parse_args(["--retries", "5", "http://x.com"])
        assert args.retries == 5

    def test_has_delay(self):
        parser = build_parser()
        args = parser.parse_args(["--delay", "2", "http://x.com"])
        assert args.delay == 2

    def test_has_cookie(self):
        parser = build_parser()
        args = parser.parse_args(["--cookie", "session=abc", "http://x.com"])
        assert args.cookie == "session=abc"

    def test_has_header(self):
        parser = build_parser()
        args = parser.parse_args(["--header", "X-Custom: yes", "http://x.com"])
        assert args.header == ["X-Custom: yes"]


class TestParseSpecEdgeCases:
    def test_v3_with_empty_info(self):
        spec = {"openapi": "3.0.0", "info": {}, "paths": {}}
        title, version, _desc, _servers, _endpoints, _schemas = _parse_openapi_v3(spec)
        assert title == ""
        assert version == ""

    def test_v2_without_host(self):
        spec = {"swagger": "2.0", "info": {"title": "NoHost", "version": "1"}, "paths": {}}
        _title, _version, _desc, servers, _endpoints, _schemas = _parse_openapi_v2(spec)
        assert servers == []

    def test_v3_with_malformed_parameters(self):
        spec = {"paths": {"/x": {"get": {"parameters": "not a list"}}}}
        _, _, _, _, endpoints, _ = _parse_openapi_v3(spec)
        assert endpoints[0].parameters == []

    def test_parse_spec_dict_not_dict(self):
        assert parse_spec(b"[1,2,3]", "application/json") is None

    def test_v2_with_no_schemes(self):
        spec = {"swagger": "2.0", "host": "x.com", "basePath": "/api", "info": {"title": "", "version": ""}, "paths": {}}
        _, _, _, servers, _, _ = _parse_openapi_v2(spec)
        assert len(servers) == 1
        assert "https://" in servers[0]
