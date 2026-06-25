from __future__ import annotations

import argparse
import json

import pytest

from graphqlplayground import (
    DEFAULT_PATHS,
    INTROSPECTION_QUERY,
    GraphqlEndpoint,
    _load_paths_from_args,
    build_parser,
    detect_tool,
    parse_introspection,
)


class TestGraphqlEndpoint:
    def test_frozen(self):
        ep = GraphqlEndpoint(url="http://x.com/graphql", tool="graphiql", status=200)
        with pytest.raises(AttributeError):
            ep.tool = "nope"

    def test_defaults(self):
        ep = GraphqlEndpoint(url="http://x.com/graphql", tool="graphql", status=200)
        assert ep.supports_introspection is False
        assert ep.schema_types == []
        assert ep.query_type == ""
        assert ep.mutation_type == ""
        assert ep.subscription_type == ""
        assert ep.raw_size == 0

    def test_all_fields(self):
        ep = GraphqlEndpoint(
            url="http://x.com/graphql",
            tool="graphiql",
            status=200,
            supports_introspection=True,
            schema_types=["User (OBJECT)", "Query (OBJECT)"],
            query_type="Query",
            mutation_type="Mutation",
            subscription_type="Subscription",
            raw_size=1024,
        )
        assert ep.supports_introspection is True
        assert len(ep.schema_types) == 2
        assert ep.query_type == "Query"


class TestDetectTool:
    def test_graphiql_div_id(self):
        html = '<div id="graphiql">Loading...</div>'
        assert detect_tool(html, {}) == "graphiql"

    def test_graphiql_script(self):
        html = '<script src="graphiql.react.min.js"></script>'
        assert detect_tool(html, {}) == "graphiql"

    def test_graphiql_create(self):
        html = 'GraphiQL.create(document.getElementById("root"))'
        assert detect_tool(html, {}) == "graphiql"

    def test_playground_title(self):
        html = '<title>GraphQL Playground</title>'
        assert detect_tool(html, {}) == "playground"

    def test_playground_div(self):
        html = '<div class="playground">loading</div>'
        assert detect_tool(html, {}) == "playground"

    def test_altair_script(self):
        html = '<script src="altair-graphql/build/index.js"></script>'
        assert detect_tool(html, {}) == "altair"

    def test_altair_window(self):
        html = 'window.altair = new AltairGraphQL()'
        assert detect_tool(html, {}) == "altair"

    def test_voyager_div(self):
        html = '<div class="voyager">loading</div>'
        assert detect_tool(html, {}) == "voyager"

    def test_voyager_script(self):
        html = '<script src="graphql-voyager.min.js"></script>'
        assert detect_tool(html, {}) == "voyager"

    def test_apollo_sandbox(self):
        html = '<div id="apollo-sandbox"></div>'
        assert detect_tool(html, {}) == "apollo-sandbox"

    def test_apollo_sandbox_class(self):
        html = '<div class="ApolloSandbox"></div>'
        assert detect_tool(html, {}) == "apollo-sandbox"

    def test_graphql_response_header(self):
        html = ""
        headers = {"content-type": "application/graphql-response+json"}
        assert detect_tool(html, headers) == "graphql"

    def test_unknown_returns_unknown(self):
        html = "<html><body>Hello world</body></html>"
        assert detect_tool(html, {}) == "unknown"

    def test_empty_body(self):
        assert detect_tool("", {}) == "unknown"

    def test_graphiql_case_insensitive(self):
        html = '<DIV ID="GRAPHIQL">'
        assert detect_tool(html, {}) == "graphiql"

    def test_multiple_signatures_first_wins(self):
        html = '<div id="graphiql"><title>GraphQL Playground</title></div>'
        assert detect_tool(html, {}) == "graphiql"


class TestParseIntrospection:
    def test_basic_schema(self):
        data = {
            "data": {
                "__schema": {
                    "queryType": {"name": "Query"},
                    "mutationType": {"name": "Mutation"},
                    "subscriptionType": None,
                    "types": [
                        {"name": "Query", "kind": "OBJECT"},
                        {"name": "User", "kind": "OBJECT"},
                        {"name": "__Schema", "kind": "SCALAR"},
                    ],
                }
            }
        }
        types, query, mutation, subscription = parse_introspection(data)
        assert len(types) == 2
        assert "Query (OBJECT)" in types
        assert "User (OBJECT)" in types
        assert "__Schema" not in types[0] or all("__" not in t for t in types)
        assert query == "Query"
        assert mutation == "Mutation"
        assert subscription == ""

    def test_empty_data(self):
        types, query, _mutation, _subscription = parse_introspection({})
        assert types == []
        assert query == ""

    def test_no_data_field(self):
        types, _query, _mutation, _subscription = parse_introspection({"errors": []})
        assert types == []

    def test_nested_types_filtered(self):
        data = {
            "data": {
                "__schema": {
                    "types": [
                        {"name": "__Type", "kind": "SCALAR"},
                        {"name": "__Field", "kind": "OBJECT"},
                        {"name": "Post", "kind": "OBJECT"},
                    ]
                }
            }
        }
        types, _, _, _ = parse_introspection(data)
        assert len(types) == 1
        assert types[0] == "Post (OBJECT)"

    def test_no_query_type(self):
        data = {
            "data": {
                "__schema": {
                    "types": [{"name": "Item", "kind": "OBJECT"}]
                }
            }
        }
        types, query, _mutation, _subscription = parse_introspection(data)
        assert types == ["Item (OBJECT)"]
        assert query == ""

    def test_malformed_types(self):
        data = {"data": {"__schema": {"types": "not a list"}}}
        types, _, _, _ = parse_introspection(data)
        assert types == []


class TestIntrospectionQuery:
    def test_is_valid_json(self):
        parsed = json.loads(INTROSPECTION_QUERY)
        assert "query" in parsed
        assert "__schema" in parsed["query"]


class TestDefaultPaths:
    def test_paths_are_strings(self):
        assert all(isinstance(p, str) for p in DEFAULT_PATHS)

    def test_common_paths_present(self):
        assert "graphql" in DEFAULT_PATHS
        assert "graphiql" in DEFAULT_PATHS
        assert "playground" in DEFAULT_PATHS
        assert "altair" in DEFAULT_PATHS
        assert "voyager" in DEFAULT_PATHS

    def test_minimum_count(self):
        assert len(DEFAULT_PATHS) >= 10


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

    def test_has_introspect_flag(self):
        parser = build_parser()
        args = parser.parse_args(["--introspect", "http://x.com"])
        assert args.introspect is True

    def test_introspect_default_false(self):
        parser = build_parser()
        args = parser.parse_args(["http://x.com"])
        assert args.introspect is False

    def test_has_schema_flag(self):
        parser = build_parser()
        args = parser.parse_args(["--schema", "http://x.com"])
        assert args.show_schema is True

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

    def test_has_paths_arg(self):
        parser = build_parser()
        args = parser.parse_args(["--paths", "10", "http://x.com"])
        assert args.paths == 10
