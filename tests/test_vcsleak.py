import argparse

import pytest

from vcsleak import (
    ALL_PATHS,
    GIT_PATHS,
    HG_PATHS,
    SVN_PATHS,
    VCSLeak,
    _classify_path,
    _load_paths_from_args,
    _validate_content,
    build_parser,
)


class TestVCSLeak:
    def test_frozen(self):
        leak = VCSLeak(vcs_type="git", url="http://x.com/.git/HEAD", path=".git/HEAD")
        with pytest.raises(AttributeError):
            leak.vcs_type = "hg"

    def test_defaults(self):
        leak = VCSLeak(vcs_type="git", url="http://x.com/.git/HEAD", path=".git/HEAD")
        assert leak.status == 0
        assert leak.detail == ""
        assert leak.raw_size == 0

    def test_all_fields(self):
        leak = VCSLeak(
            vcs_type="git",
            url="http://x.com/.git/HEAD",
            path=".git/HEAD",
            status=200,
            detail="ref: refs/heads/main",
            raw_size=20,
        )
        assert leak.vcs_type == "git"
        assert leak.detail == "ref: refs/heads/main"


class TestClassifyPath:
    def test_git(self):
        assert _classify_path(".git/HEAD") == "git"
        assert _classify_path(".git/config") == "git"
        assert _classify_path(".gitignore") == "git"

    def test_svn(self):
        assert _classify_path(".svn/entries") == "svn"
        assert _classify_path(".svn/wc.db") == "svn"

    def test_hg(self):
        assert _classify_path(".hg/store/00manifest.i") == "hg"
        assert _classify_path(".hgignore") == "hg"

    def test_unknown(self):
        assert _classify_path("robots.txt") == "unknown"


class TestValidateContent:
    def test_git_head_valid(self):
        content = b"ref: refs/heads/main\n"
        ok, detail = _validate_content(".git/HEAD", content)
        assert ok is True
        assert "ref: refs/heads/main" in detail

    def test_git_head_invalid(self):
        content = b"not a git ref"
        ok, _ = _validate_content(".git/HEAD", content)
        assert ok is False

    def test_git_config_valid(self):
        content = b"[core]\n\trepositoryformatversion = 0\n\tfilemode = true"
        ok, detail = _validate_content(".git/config", content)
        assert ok is True
        assert "[core]" in detail

    def test_git_config_remote(self):
        content = b"[remote \"origin\"]\n\turl = https://github.com/x/y.git"
        ok, detail = _validate_content(".git/config", content)
        assert ok is True
        assert "[remote" in detail

    def test_git_config_empty(self):
        content = b"empty file"
        ok, _ = _validate_content(".git/config", content)
        assert ok is False

    def test_git_index_valid(self):
        content = b"DIRC" + b"\x00" * 100
        ok, detail = _validate_content(".git/index", content)
        assert ok is True
        assert "Git index" in detail

    def test_git_index_invalid(self):
        content = b"not an index"
        ok, _ = _validate_content(".git/index", content)
        assert ok is False

    def test_git_commit_msg(self):
        content = b"# Please enter the commit message"
        ok, _ = _validate_content(".git/COMMIT_EDITMSG", content)
        assert ok is True

    def test_git_packed_refs(self):
        content = b"abc123def456abc123def456abc123def456abc1 refs/heads/main\n"
        ok, _ = _validate_content(".git/packed-refs", content)
        assert ok is True

    def test_git_logs_head(self):
        content = b"abc123def456abc123def456abc123def456abc1 def456abc123def456abc123def456abc123def456abc1 Author <x@x.com> 1234567890 +0000\tcommit message\n"
        ok, _ = _validate_content(".git/logs/HEAD", content)
        assert ok is True

    def test_git_fallback(self):
        content = b"some git content here"
        ok, detail = _validate_content(".git/description", content)
        assert ok is True
        assert "some git content" in detail

    def test_svn_wc_db_valid(self):
        content = b"SQLite format 3" + b"\x00" * 100
        ok, detail = _validate_content(".svn/wc.db", content)
        assert ok is True
        assert "SQLite" in detail

    def test_svn_wc_db_invalid(self):
        content = b"not sqlite"
        ok, _ = _validate_content(".svn/wc.db", content)
        assert ok is False

    def test_svn_entries_valid(self):
        content = b"12\n\ndir\nhttps://svn.example.com/repo\n"
        ok, _ = _validate_content(".svn/entries", content)
        assert ok is True

    def test_hg_manifest_valid(self):
        content = b"abc123def456abc123def456abc123def456abc1 644 path/to/file\n"
        ok, _ = _validate_content(".hg/store/00manifest.i", content)
        assert ok is True

    def test_hg_dirstate_valid(self):
        content = b"n   644   abc123def456abc123def456abc123def456abc1   path/file.txt\n"
        ok, _ = _validate_content(".hg/dirstate", content)
        assert ok is True

    def test_empty_content(self):
        ok, detail = _validate_content(".git/HEAD", b"")
        assert ok is False
        assert detail == ""

    def test_unknown_path(self):
        content = b"some content"
        ok, _ = _validate_content("robots.txt", content)
        assert ok is True

    def test_git_description_default(self):
        content = b"Unnamed repository; edit this file 'description' to name the repository."
        ok, _ = _validate_content(".git/description", content)
        assert ok is False


class TestPathConstants:
    def test_all_paths_are_strings(self):
        assert all(isinstance(p, str) for p in ALL_PATHS)

    def test_git_paths_have_git_prefix(self):
        assert all(p.startswith(".git") for p in GIT_PATHS)

    def test_svn_paths_have_svn_prefix(self):
        assert all(p.startswith(".svn") for p in SVN_PATHS)

    def test_hg_paths_have_hg_prefix(self):
        assert all(p.startswith(".hg") for p in HG_PATHS)

    def test_git_has_head(self):
        assert ".git/HEAD" in GIT_PATHS

    def test_svn_has_entries(self):
        assert ".svn/entries" in SVN_PATHS

    def test_hg_has_manifest(self):
        assert ".hg/store/00manifest.i" in HG_PATHS

    def test_minimum_count(self):
        assert len(ALL_PATHS) >= 20

    def test_minimum_git(self):
        assert len(GIT_PATHS) >= 8

    def test_minimum_svn(self):
        assert len(SVN_PATHS) >= 3

    def test_minimum_hg(self):
        assert len(HG_PATHS) >= 3


class TestLoadPaths:
    def test_default_returns_none(self):
        args = argparse.Namespace(git_only=False, svn_only=False, hg_only=False)
        result = _load_paths_from_args(args)
        assert result is None

    def test_git_only(self):
        args = argparse.Namespace(git_only=True, svn_only=False, hg_only=False)
        result = _load_paths_from_args(args)
        assert result == GIT_PATHS

    def test_svn_only(self):
        args = argparse.Namespace(git_only=False, svn_only=True, hg_only=False)
        result = _load_paths_from_args(args)
        assert result == SVN_PATHS

    def test_hg_only(self):
        args = argparse.Namespace(git_only=False, svn_only=False, hg_only=True)
        result = _load_paths_from_args(args)
        assert result == HG_PATHS

    def test_git_takes_priority(self):
        args = argparse.Namespace(git_only=True, svn_only=True, hg_only=True)
        result = _load_paths_from_args(args)
        assert result == GIT_PATHS


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
        args = parser.parse_args(["--concurrency", "50", "http://x.com"])
        assert args.concurrency == 50

    def test_default_concurrency(self):
        parser = build_parser()
        args = parser.parse_args(["http://x.com"])
        assert args.concurrency == 30

    def test_git_only(self):
        parser = build_parser()
        args = parser.parse_args(["--git-only", "http://x.com"])
        assert args.git_only is True

    def test_svn_only(self):
        parser = build_parser()
        args = parser.parse_args(["--svn-only", "http://x.com"])
        assert args.svn_only is True

    def test_hg_only(self):
        parser = build_parser()
        args = parser.parse_args(["--hg-only", "http://x.com"])
        assert args.hg_only is True

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
