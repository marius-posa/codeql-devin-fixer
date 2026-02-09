#!/usr/bin/env python3
"""Tests for knowledge.py - Devin Knowledge API client."""

import json
import sys
import os
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(__file__))

from knowledge import (
    KNOWLEDGE_NAME_PREFIX,
    _classify_fix_pattern,
    _make_knowledge_name,
    build_knowledge_context,
    create_knowledge,
    delete_knowledge,
    find_knowledge_for_cwe,
    list_knowledge,
    store_fix_knowledge,
    update_knowledge,
)


class TestKnowledgeNaming(unittest.TestCase):
    def test_make_knowledge_name(self):
        name = _make_knowledge_name("injection", 1)
        self.assertEqual(name, f"{KNOWLEDGE_NAME_PREFIX}/injection/batch-1")

    def test_make_knowledge_name_string_batch(self):
        name = _make_knowledge_name("xss", "42")
        self.assertEqual(name, f"{KNOWLEDGE_NAME_PREFIX}/xss/batch-42")

    def test_classify_fix_pattern_known(self):
        self.assertIn("parameterized", _classify_fix_pattern("injection"))
        self.assertIn("encoding", _classify_fix_pattern("xss"))
        self.assertIn("canonicalization", _classify_fix_pattern("path-traversal"))

    def test_classify_fix_pattern_unknown(self):
        self.assertEqual(_classify_fix_pattern("unknown-family"), "security fix pattern")


class TestListKnowledge(unittest.TestCase):
    @patch("knowledge.requests.request")
    def test_list_returns_list(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [{"id": "1", "name": "test"}]
        mock_resp.raise_for_status = MagicMock()
        mock_req.return_value = mock_resp

        result = list_knowledge("test-key")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["name"], "test")

    @patch("knowledge.requests.request")
    def test_list_returns_dict_with_items(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"items": [{"id": "1"}]}
        mock_resp.raise_for_status = MagicMock()
        mock_req.return_value = mock_resp

        result = list_knowledge("test-key")
        self.assertEqual(len(result), 1)


class TestCreateKnowledge(unittest.TestCase):
    @patch("knowledge.requests.request")
    def test_create_basic(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"id": "new-id", "name": "test"}
        mock_resp.raise_for_status = MagicMock()
        mock_req.return_value = mock_resp

        result = create_knowledge(
            api_key="test-key",
            name="test-name",
            body="test body",
            trigger_description="when testing",
        )
        self.assertEqual(result["id"], "new-id")

        call_kwargs = mock_req.call_args
        payload = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json")
        self.assertEqual(payload["name"], "test-name")
        self.assertEqual(payload["body"], "test body")
        self.assertNotIn("pinned_repo", payload)

    @patch("knowledge.requests.request")
    def test_create_with_pinned_repo(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"id": "new-id"}
        mock_resp.raise_for_status = MagicMock()
        mock_req.return_value = mock_resp

        create_knowledge(
            api_key="test-key",
            name="test",
            body="body",
            trigger_description="trigger",
            pinned_repo="owner/repo",
        )
        call_kwargs = mock_req.call_args
        payload = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json")
        self.assertEqual(payload["pinned_repo"], "owner/repo")


class TestUpdateKnowledge(unittest.TestCase):
    @patch("knowledge.requests.request")
    def test_update(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"id": "note-1", "body": "updated"}
        mock_resp.raise_for_status = MagicMock()
        mock_req.return_value = mock_resp

        result = update_knowledge("test-key", "note-1", body="updated")
        self.assertEqual(result["body"], "updated")
        args = mock_req.call_args
        self.assertIn("/knowledge/note-1", args[0][1])


class TestDeleteKnowledge(unittest.TestCase):
    @patch("knowledge.requests.request")
    def test_delete(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.status_code = 204
        mock_resp.raise_for_status = MagicMock()
        mock_req.return_value = mock_resp

        result = delete_knowledge("test-key", "note-1")
        self.assertEqual(result, {})


class TestStoreFixKnowledge(unittest.TestCase):
    @patch("knowledge.create_knowledge")
    def test_store_fix(self, mock_create):
        mock_create.return_value = {"id": "new-knowledge"}

        result = store_fix_knowledge(
            api_key="test-key",
            cwe_family="injection",
            batch_id=3,
            pr_url="https://github.com/org/repo/pull/1",
            diff_summary="Fixed SQL injection with parameterized queries",
            issue_count=2,
            severity_tier="high",
            repo_url="https://github.com/org/repo",
        )
        self.assertEqual(result["id"], "new-knowledge")

        call_kwargs = mock_create.call_args.kwargs
        self.assertIn("injection", call_kwargs["name"])
        self.assertIn("batch-3", call_kwargs["name"])
        self.assertIn("parameterized", call_kwargs["trigger_description"])
        self.assertIn("injection", call_kwargs["trigger_description"])
        self.assertEqual(call_kwargs["pinned_repo"], "org/repo")


class TestFindKnowledgeForCwe(unittest.TestCase):
    @patch("knowledge.list_knowledge")
    def test_find_matching(self, mock_list):
        mock_list.return_value = [
            {"name": f"{KNOWLEDGE_NAME_PREFIX}/injection/batch-1", "id": "1"},
            {"name": f"{KNOWLEDGE_NAME_PREFIX}/xss/batch-2", "id": "2"},
            {"name": f"{KNOWLEDGE_NAME_PREFIX}/injection/batch-3", "id": "3"},
        ]
        results = find_knowledge_for_cwe("test-key", "injection")
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]["id"], "1")
        self.assertEqual(results[1]["id"], "3")

    @patch("knowledge.list_knowledge")
    def test_find_none(self, mock_list):
        mock_list.return_value = [
            {"name": f"{KNOWLEDGE_NAME_PREFIX}/xss/batch-1", "id": "1"},
        ]
        results = find_knowledge_for_cwe("test-key", "injection")
        self.assertEqual(len(results), 0)


class TestBuildKnowledgeContext(unittest.TestCase):
    @patch("knowledge.find_knowledge_for_cwe")
    def test_build_context_with_entries(self, mock_find):
        mock_find.return_value = [
            {
                "name": f"{KNOWLEDGE_NAME_PREFIX}/injection/batch-1",
                "body": "Fixed SQL injection with parameterized queries\nDiff: ...",
            },
        ]
        context = build_knowledge_context("test-key", "injection")
        self.assertIn("Verified Fix Patterns", context)
        self.assertIn("parameterized queries", context)
        self.assertIn("Reference Fix 1", context)

    @patch("knowledge.find_knowledge_for_cwe")
    def test_build_context_empty(self, mock_find):
        mock_find.return_value = []
        context = build_knowledge_context("test-key", "injection")
        self.assertEqual(context, "")

    @patch("knowledge.find_knowledge_for_cwe")
    def test_build_context_truncates_long_body(self, mock_find):
        mock_find.return_value = [
            {
                "name": f"{KNOWLEDGE_NAME_PREFIX}/injection/batch-1",
                "body": "x" * 3000,
            },
        ]
        context = build_knowledge_context("test-key", "injection")
        self.assertIn("truncated", context)


if __name__ == "__main__":
    unittest.main()
