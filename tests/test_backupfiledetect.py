#!/usr/bin/env python3
"""Testes unitarios do modulo de deteccao de backup files."""
import argparse

import httpx
import pytest
import respx

from backupfiledetect import (
    ALL_PATHS,
    ALL_TYPES,
    ARCHIVE_PATHS,
    BAK_PATHS,
    ORIG_TMP_PATHS,
    SQL_DUMP_PATHS,
    SWP_PATHS,
    TILDE_PATHS,
    BackupFile,
    _classify_backup,
    _load_paths_from_args,
    _validate_content,
    build_parser,
    print_results,
    scan_backups,
)

# ── Dataclass ────────────────────────────────────────────────────────────────


class TestBackupFile:
    def test_frozen(self):
        b = BackupFile(backup_type="x", url="y", path="z")
        with pytest.raises(AttributeError):
            b.url = "w"  # type: ignore[misc]

    def test_defaults(self):
        b = BackupFile(backup_type="x", url="y", path="z")
        assert b.status == 0
        assert b.detail == ""
        assert b.raw_size == 0

    def test_all_fields(self):
        b = BackupFile(
            backup_type="sql", url="http://x.com/dump.sql", path="dump.sql",
            status=200, detail="SQL dump", raw_size=1024,
        )
        assert b.backup_type == "sql"
        assert b.raw_size == 1024


# ── _classify_backup ──────────────────────────────────────────────────────────


class TestClassifyBackup:
    def test_bak_type(self):
        assert _classify_backup("config.php.bak") == "bak"

    def test_old_type(self):
        assert _classify_backup("config.php.old") == "bak"

    def test_backup_type(self):
        assert _classify_backup("config.php.backup") == "bak"

    def test_swp_type(self):
        assert _classify_backup(".config.php.swp") == "swp"

    def test_swo_type(self):
        assert _classify_backup(".config.php.swo") == "swp"

    def test_tilde_type(self):
        assert _classify_backup("config.php~") == "tilde"

    def test_sql_type(self):
        assert _classify_backup("dump.sql") == "sql"

    def test_sql_gz_type(self):
        assert _classify_backup("dump.sql.gz") == "sql"

    def test_zip_type(self):
        assert _classify_backup("backup.zip") == "archive"

    def test_tar_gz_type(self):
        assert _classify_backup("site.tar.gz") == "archive"

    def test_tgz_type(self):
        assert _classify_backup("backup.tgz") == "archive"

    def test_orig_type(self):
        assert _classify_backup("index.php.orig") == "orig_tmp"

    def test_tmp_type(self):
        assert _classify_backup("config.php.tmp") == "orig_tmp"

    def test_save_type(self):
        assert _classify_backup("wp-config.php.save") == "bak"

    def test_unknown_fallback_bak(self):
        assert _classify_backup("unknown.bak") == "bak"

    def test_unknown_fallback_swp(self):
        assert _classify_backup("unknown.swp") == "swp"

    def test_in_all_types(self):
        for btype, paths in ALL_TYPES.items():
            for p in paths:
                if p == "config.php.save":
                    continue
                assert _classify_backup(p) == btype


# ── _validate_content ────────────────────────────────────────────────────────


class TestValidateContent:
    def test_empty_content(self):
        ok, _ = _validate_content("config.php.bak", b"")
        assert ok is False

    def test_bak_valid(self):
        ok, detail = _validate_content("config.php.bak", b"<?php $db='x'; ?>")
        assert ok is True
        assert detail

    def test_old_valid(self):
        ok, _ = _validate_content("config.php.old", b"old content here")
        assert ok is True

    def test_tilde_valid(self):
        ok, _ = _validate_content("config.php~", b"tilde backup")
        assert ok is True

    def test_sql_create_table(self):
        ok, detail = _validate_content("dump.sql", b"CREATE TABLE users (id INT);")
        assert ok is True
        assert "create table" in detail.lower()

    def test_sql_insert_into(self):
        ok, detail = _validate_content("dump.sql", b"INSERT INTO users VALUES (1);")
        assert ok is True
        assert any(kw in detail.lower() for kw in ("insert into", "values"))

    def test_sql_invalid(self):
        ok, _ = _validate_content("dump.sql", b"this is not sql at all")
        assert ok is False

    def test_sql_gzip_valid(self):
        ok, detail = _validate_content("dump.sql.gz", b"\x1f\x8b" + b"\x00" * 100)
        assert ok is True
        assert "GZIP" in detail

    def test_zip_valid(self):
        ok, detail = _validate_content("backup.zip", b"PK" + b"\x00" * 100)
        assert ok is True
        assert "ZIP" in detail

    def test_gzip_valid(self):
        ok, detail = _validate_content("site.tar.gz", b"\x1f\x8b" + b"\x00" * 100)
        assert ok is True
        assert "GZIP" in detail

    def test_bzip2_valid(self):
        ok, detail = _validate_content("backup.tar.bz2", b"BZh" + b"\x00" * 100)
        assert ok is True
        assert "BZIP2" in detail

    def test_swp_vim_magic(self):
        ok, detail = _validate_content(".config.php.swp", b"\x0b" + b"\x00" * 100)
        assert ok is True
        assert "Vim" in detail

    def test_swp_nonstandard(self):
        ok, _detail = _validate_content(".config.php.swp", b"\xff" + b"\x00" * 200)
        assert ok is True

    def test_swp_too_small(self):
        ok, _ = _validate_content(".config.php.swp", b"\xff\x00\x01")
        assert ok is False


# ── Path constants ────────────────────────────────────────────────────────────


class TestPathConstants:
    def test_bak_not_empty(self):
        assert len(BAK_PATHS) >= 10

    def test_swp_not_empty(self):
        assert len(SWP_PATHS) >= 5

    def test_tilde_not_empty(self):
        assert len(TILDE_PATHS) >= 5

    def test_sql_not_empty(self):
        assert len(SQL_DUMP_PATHS) >= 5

    def test_archive_not_empty(self):
        assert len(ARCHIVE_PATHS) >= 5

    def test_orig_tmp_not_empty(self):
        assert len(ORIG_TMP_PATHS) >= 5

    def test_all_paths_combined(self):
        assert len(ALL_PATHS) > 30

    def test_all_strings(self):
        for p in ALL_PATHS:
            assert isinstance(p, str)

    def test_no_leading_slash(self):
        for p in ALL_PATHS:
            assert not p.startswith("/")


# ── _load_paths_from_args ────────────────────────────────────────────────────


class TestLoadPathsFromArgs:
    def test_all_returns_none(self):
        args = argparse.Namespace(backup_type="all")
        assert _load_paths_from_args(args) is None

    def test_bak_returns_bak_paths(self):
        args = argparse.Namespace(backup_type="bak")
        assert _load_paths_from_args(args) == BAK_PATHS

    def test_swp_returns_swp_paths(self):
        args = argparse.Namespace(backup_type="swp")
        assert _load_paths_from_args(args) == SWP_PATHS

    def test_sql_returns_sql_paths(self):
        args = argparse.Namespace(backup_type="sql")
        assert _load_paths_from_args(args) == SQL_DUMP_PATHS


# ── build_parser ──────────────────────────────────────────────────────────────


class TestBuildParser:
    def test_has_url(self):
        args = build_parser().parse_args(["http://x.com"])
        assert args.url == "http://x.com"

    def test_has_list(self):
        args = build_parser().parse_args(["-l", "urls.txt"])
        assert args.target_list == "urls.txt"

    def test_has_type(self):
        args = build_parser().parse_args(["--type", "sql"])
        assert args.backup_type == "sql"

    def test_has_concurrency(self):
        args = build_parser().parse_args(["--concurrency", "50"])
        assert args.concurrency == 50

    def test_default_type_all(self):
        args = build_parser().parse_args([])
        assert args.backup_type == "all"


# ── print_results ─────────────────────────────────────────────────────────────


class TestPrintResults:
    def test_empty(self, capsys):
        print_results([])
        out = capsys.readouterr().out
        assert "Nenhum" in out

    def test_with_results(self, capsys):
        results = [
            BackupFile(backup_type="sql", url="http://x.com/dump.sql", path="dump.sql",
                       status=200, detail="SQL dump", raw_size=1024),
        ]
        print_results(results)
        out = capsys.readouterr().out
        assert "dump.sql" in out


# ── scan_backups (mock) ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_scan_backups_no_results():
    with respx.mock:
        respx.route(method="HEAD", url__startswith="http://x.com/").mock(
            return_value=httpx.Response(404),
        )
        respx.route(method="GET", url__startswith="http://x.com/").mock(
            return_value=httpx.Response(404),
        )
        backups = await scan_backups(
            base_url="http://x.com/",
            timeout=5.0,
            concurrency=5,
            user_agent="test/1.0",
        )
        assert backups == []


@pytest.mark.asyncio
async def test_scan_backups_finds_bak():
    with respx.mock:
        respx.route(method="HEAD", url="http://x.com/config.php.bak").mock(
            return_value=httpx.Response(200, headers={"content-length": "100"}),
        )
        respx.route(method="GET", url="http://x.com/config.php.bak").mock(
            return_value=httpx.Response(200, content=b"<?php $db='test'; ?>"),
        )
        # All other paths return 404
        respx.route(method="HEAD").mock(return_value=httpx.Response(404))
        respx.route(method="GET").mock(return_value=httpx.Response(404))

        backups = await scan_backups(
            base_url="http://x.com/",
            timeout=5.0,
            concurrency=5,
            user_agent="test/1.0",
        )
        paths = [b.path for b in backups]
        assert "config.php.bak" in paths


@pytest.mark.asyncio
async def test_scan_backups_finds_sql():
    with respx.mock:
        respx.route(method="HEAD", url="http://x.com/dump.sql").mock(
            return_value=httpx.Response(200, headers={"content-length": "200"}),
        )
        respx.route(method="GET", url="http://x.com/dump.sql").mock(
            return_value=httpx.Response(200, content=b"CREATE TABLE users (id INT);\nINSERT INTO users VALUES (1);"),
        )
        respx.route(method="HEAD").mock(return_value=httpx.Response(404))
        respx.route(method="GET").mock(return_value=httpx.Response(404))

        backups = await scan_backups(
            base_url="http://x.com/",
            timeout=5.0,
            concurrency=5,
            user_agent="test/1.0",
        )
        types = [b.backup_type for b in backups]
        assert "sql" in types


@pytest.mark.asyncio
async def test_scan_backups_skips_invalid_sql():
    with respx.mock:
        respx.route(method="HEAD", url="http://x.com/dump.sql").mock(
            return_value=httpx.Response(200, headers={"content-length": "50"}),
        )
        respx.route(method="GET", url="http://x.com/dump.sql").mock(
            return_value=httpx.Response(200, content=b"this is not sql at all"),
        )
        respx.route(method="HEAD").mock(return_value=httpx.Response(404))
        respx.route(method="GET").mock(return_value=httpx.Response(404))

        backups = await scan_backups(
            base_url="http://x.com/",
            timeout=5.0,
            concurrency=5,
            user_agent="test/1.0",
        )
        assert backups == []


@pytest.mark.asyncio
async def test_scan_backups_skips_large_content():
    with respx.mock:
        respx.route(method="HEAD", url="http://x.com/config.php.bak").mock(
            return_value=httpx.Response(200, headers={"content-length": "20000000"}),
        )
        respx.route(method="HEAD").mock(return_value=httpx.Response(404))
        respx.route(method="GET").mock(return_value=httpx.Response(404))

        backups = await scan_backups(
            base_url="http://x.com/",
            timeout=5.0,
            concurrency=5,
            user_agent="test/1.0",
        )
        assert backups == []


@pytest.mark.asyncio
async def test_scan_backups_skips_405_head():
    """405 em HEAD deve ser ignorado (prosseguir com GET)."""
    with respx.mock:
        respx.route(method="HEAD", url="http://x.com/config.php.bak").mock(
            return_value=httpx.Response(405),
        )
        respx.route(method="GET", url="http://x.com/config.php.bak").mock(
            return_value=httpx.Response(200, content=b"backup content"),
        )
        respx.route(method="HEAD").mock(return_value=httpx.Response(404))
        respx.route(method="GET").mock(return_value=httpx.Response(404))

        backups = await scan_backups(
            base_url="http://x.com/",
            timeout=5.0,
            concurrency=5,
            user_agent="test/1.0",
        )
        assert any(b.path == "config.php.bak" for b in backups)


@pytest.mark.asyncio
async def test_scan_backups_head_500_skips():
    with respx.mock:
        respx.route(method="HEAD", url="http://x.com/config.php.bak").mock(
            return_value=httpx.Response(500),
        )
        respx.route(method="HEAD").mock(return_value=httpx.Response(404))
        respx.route(method="GET").mock(return_value=httpx.Response(404))

        backups = await scan_backups(
            base_url="http://x.com/",
            timeout=5.0,
            concurrency=5,
            user_agent="test/1.0",
        )
        assert backups == []


@pytest.mark.asyncio
async def test_scan_backups_finds_zip():
    with respx.mock:
        respx.route(method="HEAD", url="http://x.com/backup.zip").mock(
            return_value=httpx.Response(200, headers={"content-length": "5000"}),
        )
        respx.route(method="GET", url="http://x.com/backup.zip").mock(
            return_value=httpx.Response(200, content=b"PK" + b"\x00" * 5000),
        )
        respx.route(method="HEAD").mock(return_value=httpx.Response(404))
        respx.route(method="GET").mock(return_value=httpx.Response(404))

        backups = await scan_backups(
            base_url="http://x.com/",
            timeout=5.0,
            concurrency=5,
            user_agent="test/1.0",
        )
        assert any(b.backup_type == "archive" for b in backups)


@pytest.mark.asyncio
async def test_scan_backups_skips_archive_over_50mb():
    with respx.mock:
        respx.route(method="HEAD", url="http://x.com/backup.zip").mock(
            return_value=httpx.Response(200, headers={"content-length": "60000000"}),
        )
        respx.route(method="HEAD").mock(return_value=httpx.Response(404))
        respx.route(method="GET").mock(return_value=httpx.Response(404))

        backups = await scan_backups(
            base_url="http://x.com/",
            timeout=5.0,
            concurrency=5,
            user_agent="test/1.0",
        )
        assert backups == []


@pytest.mark.asyncio
async def test_scan_backups_fetch_error():
    with respx.mock:
        respx.route(method="HEAD", url__startswith="http://x.com/").mock(
            side_effect=httpx.ConnectError("refused"),
        )
        respx.route(method="GET", url__startswith="http://x.com/").mock(
            side_effect=httpx.ConnectError("refused"),
        )
        backups = await scan_backups(
            base_url="http://x.com/",
            timeout=5.0,
            concurrency=5,
            user_agent="test/1.0",
        )
        assert backups == []


@pytest.mark.asyncio
async def test_scan_backups_custom_type_filter():
    with respx.mock:
        respx.route(method="HEAD", url__startswith="http://x.com/").mock(
            return_value=httpx.Response(404),
        )
        respx.route(method="GET", url__startswith="http://x.com/").mock(
            return_value=httpx.Response(404),
        )
        backups = await scan_backups(
            base_url="http://x.com/",
            timeout=5.0,
            concurrency=5,
            user_agent="test/1.0",
            custom_paths=["only-this.sql"],
        )
        assert backups == []


@pytest.mark.asyncio
async def test_scan_backups_head_405_followed_by_get():
    """HEAD retorna 405, GET retorna backup."""
    with respx.mock:
        respx.route(method="HEAD", url="http://x.com/config.php.bak").mock(
            return_value=httpx.Response(405),
        )
        respx.route(method="GET", url="http://x.com/config.php.bak").mock(
            return_value=httpx.Response(200, content=b"real backup data here"),
        )
        respx.route(method="HEAD").mock(return_value=httpx.Response(404))
        respx.route(method="GET").mock(return_value=httpx.Response(404))

        backups = await scan_backups(
            base_url="http://x.com/",
            timeout=5.0,
            concurrency=5,
            user_agent="test/1.0",
        )
        assert any(b.path == "config.php.bak" for b in backups)
