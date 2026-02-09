var DEMO_DATA = {
  "runs": [
    {
      "target_repo": "https://github.com/acme-corp/web-platform",
      "fork_url": "https://github.com/acme-corp-forks/web-platform",
      "run_number": 1,
      "run_id": "80729735682",
      "run_url": "https://github.com/acme-corp/codeql-devin-fixer/actions/runs/14047709743",
      "run_label": "run-1-2025-11-04-171700",
      "timestamp": "2025-11-04T17:17:00+00:00",
      "issues_found": 14,
      "severity_breakdown": {
        "medium": 5,
        "critical": 3,
        "high": 4,
        "low": 2
      },
      "category_breakdown": {
        "injection": 2,
        "auth-bypass": 3,
        "ssrf": 2,
        "xss": 3,
        "crypto": 1,
        "insecure-deserialization": 1,
        "info-disclosure": 1,
        "path-traversal": 1
      },
      "batches_created": 4,
      "sessions": [
        {
          "session_id": "devin-dd1006b888cd41edaf56adb1ed1acfd3",
          "session_url": "https://app.devin.ai/sessions/dd1006b888cd41edaf56adb1ed1acfd3",
          "batch_id": 1,
          "status": "finished",
          "issue_ids": [
            "ISSUE-001-001",
            "ISSUE-001-002",
            "ISSUE-001-003"
          ],
          "pr_url": "https://github.com/acme-corp-forks/web-platform/pull/1"
        },
        {
          "session_id": "devin-d17b1c0d0bc84abeb6598e5a7f9e173a",
          "session_url": "https://app.devin.ai/sessions/d17b1c0d0bc84abeb6598e5a7f9e173a",
          "batch_id": 2,
          "status": "stopped",
          "issue_ids": [
            "ISSUE-001-004",
            "ISSUE-001-005",
            "ISSUE-001-006"
          ],
          "pr_url": ""
        },
        {
          "session_id": "devin-d7092aa13d7c4f19857eac9bc1bfad8f",
          "session_url": "https://app.devin.ai/sessions/d7092aa13d7c4f19857eac9bc1bfad8f",
          "batch_id": 3,
          "status": "stopped",
          "issue_ids": [
            "ISSUE-001-007",
            "ISSUE-001-008",
            "ISSUE-001-009"
          ],
          "pr_url": ""
        },
        {
          "session_id": "devin-b0d8c42740904edf93a79ec175364837",
          "session_url": "https://app.devin.ai/sessions/b0d8c42740904edf93a79ec175364837",
          "batch_id": 4,
          "status": "finished",
          "issue_ids": [
            "ISSUE-001-010",
            "ISSUE-001-011",
            "ISSUE-001-012"
          ],
          "pr_url": ""
        }
      ],
      "issue_fingerprints": [
        {
          "id": "ISSUE-001-001",
          "fingerprint": "3a5da65914677b758412767574a8b024",
          "rule_id": "py/sql-injection",
          "severity_tier": "medium",
          "cwe_family": "injection",
          "file": "src/db/queries.py",
          "start_line": 184,
          "description": "Potential injection vulnerability in queries.py",
          "resolution": "",
          "code_churn": 2
        },
        {
          "id": "ISSUE-001-002",
          "fingerprint": "5fbe4f4b3b2d8022e4e2c6a46dc248ad",
          "rule_id": "py/insecure-auth",
          "severity_tier": "critical",
          "cwe_family": "auth-bypass",
          "file": "src/middleware/auth.py",
          "start_line": 205,
          "description": "Potential auth bypass vulnerability in auth.py",
          "resolution": "",
          "code_churn": 0
        },
        {
          "id": "ISSUE-001-003",
          "fingerprint": "b5cb05bcd6e1cf9a4e3246b829b7eaa1",
          "rule_id": "js/missing-auth-check",
          "severity_tier": "high",
          "cwe_family": "auth-bypass",
          "file": "src/middleware/auth.py",
          "start_line": 385,
          "description": "Potential auth bypass vulnerability in auth.py",
          "resolution": "",
          "code_churn": 3
        },
        {
          "id": "ISSUE-001-004",
          "fingerprint": "bd124f51071dee9e344afce48f486ed6",
          "rule_id": "py/ssrf",
          "severity_tier": "medium",
          "cwe_family": "ssrf",
          "file": "src/services/WebhookClient.java",
          "start_line": 437,
          "description": "Potential ssrf vulnerability in WebhookClient.java",
          "resolution": "",
          "code_churn": 2
        },
        {
          "id": "ISSUE-001-005",
          "fingerprint": "79d396a867bb761930e444c427feb511",
          "rule_id": "js/xss",
          "severity_tier": "medium",
          "cwe_family": "xss",
          "file": "src/views/dashboard.js",
          "start_line": 130,
          "description": "Potential xss vulnerability in dashboard.js",
          "resolution": "",
          "code_churn": 2
        },
        {
          "id": "ISSUE-001-006",
          "fingerprint": "ea738cede9339a6c2200506d9fd5fa06",
          "rule_id": "py/weak-crypto",
          "severity_tier": "low",
          "cwe_family": "crypto",
          "file": "src/utils/encryption.js",
          "start_line": 157,
          "description": "Potential crypto vulnerability in encryption.js",
          "resolution": "",
          "code_churn": 3
        },
        {
          "id": "ISSUE-001-007",
          "fingerprint": "3f4952331c63173e97c45c8ab1c1e276",
          "rule_id": "py/insecure-auth",
          "severity_tier": "medium",
          "cwe_family": "auth-bypass",
          "file": "src/api/middleware/auth.js",
          "start_line": 197,
          "description": "Potential auth bypass vulnerability in auth.js",
          "resolution": "",
          "code_churn": 1
        },
        {
          "id": "ISSUE-001-008",
          "fingerprint": "9ad5eb487d3e35acf23245913213c717",
          "rule_id": "js/stored-xss",
          "severity_tier": "medium",
          "cwe_family": "xss",
          "file": "src/views/dashboard.js",
          "start_line": 104,
          "description": "Potential xss vulnerability in dashboard.js",
          "resolution": "",
          "code_churn": 1
        },
        {
          "id": "ISSUE-001-009",
          "fingerprint": "dda92094614a635444544b6e31519887",
          "rule_id": "java/ssrf",
          "severity_tier": "critical",
          "cwe_family": "ssrf",
          "file": "src/services/webhook_sender.py",
          "start_line": 368,
          "description": "Potential ssrf vulnerability in webhook_sender.py",
          "resolution": "",
          "code_churn": 2
        },
        {
          "id": "ISSUE-001-010",
          "fingerprint": "5d04ce354d90f1a400f9a23b7d904494",
          "rule_id": "py/sql-injection",
          "severity_tier": "low",
          "cwe_family": "injection",
          "file": "src/api/controllers/users.py",
          "start_line": 431,
          "description": "Potential injection vulnerability in users.py",
          "resolution": "",
          "code_churn": 2
        },
        {
          "id": "ISSUE-001-011",
          "fingerprint": "7e032dc84dbcfb02c5932e671336a19c",
          "rule_id": "js/xss",
          "severity_tier": "high",
          "cwe_family": "xss",
          "file": "src/views/dashboard.js",
          "start_line": 468,
          "description": "Potential xss vulnerability in dashboard.js",
          "resolution": "",
          "code_churn": 2
        },
        {
          "id": "ISSUE-001-012",
          "fingerprint": "9078605bfe2fd3793d3daa01b5cdc36d",
          "rule_id": "java/unsafe-deserialization",
          "severity_tier": "high",
          "cwe_family": "insecure-deserialization",
          "file": "src/services/DataImporter.java",
          "start_line": 94,
          "description": "Potential insecure deserialization vulnerability in DataImporter.java",
          "resolution": "",
          "code_churn": 2
        },
        {
          "id": "ISSUE-001-013",
          "fingerprint": "33fbfe299b3d367a2d6a2a45709b0d60",
          "rule_id": "java/information-exposure",
          "severity_tier": "critical",
          "cwe_family": "info-disclosure",
          "file": "src/handlers/ExceptionMapper.java",
          "start_line": 241,
          "description": "Potential info disclosure vulnerability in ExceptionMapper.java",
          "resolution": "",
          "code_churn": 3
        },
        {
          "id": "ISSUE-001-014",
          "fingerprint": "77588c12f04408bfc94461964c5d50f3",
          "rule_id": "java/path-injection",
          "severity_tier": "high",
          "cwe_family": "path-traversal",
          "file": "src/api/upload.js",
          "start_line": 69,
          "description": "Potential path traversal vulnerability in upload.js",
          "resolution": "",
          "code_churn": 0
        }
      ]
    },
    {
      "target_repo": "https://github.com/acme-corp/web-platform",
      "fork_url": "https://github.com/acme-corp-forks/web-platform",
      "run_number": 2,
      "run_id": "82681300933",
      "run_url": "https://github.com/acme-corp/codeql-devin-fixer/actions/runs/13944899549",
      "run_label": "run-2-2025-11-12-091400",
      "timestamp": "2025-11-12T09:14:00+00:00",
      "issues_found": 1,
      "severity_breakdown": {
        "low": 1
      },
      "category_breakdown": {
        "info-disclosure": 1
      },
      "batches_created": 1,
      "sessions": [
        {
          "session_id": "devin-d39dcf04246b43c496e3a9a6e3db3182",
          "session_url": "https://app.devin.ai/sessions/d39dcf04246b43c496e3a9a6e3db3182",
          "batch_id": 1,
          "status": "finished",
          "issue_ids": [
            "ISSUE-002-001"
          ],
          "pr_url": "https://github.com/acme-corp-forks/web-platform/pull/2"
        }
      ],
      "issue_fingerprints": [
        {
          "id": "ISSUE-002-001",
          "fingerprint": "b4981d1188f5bce207bf776330c5c27a",
          "rule_id": "java/information-exposure",
          "severity_tier": "low",
          "cwe_family": "info-disclosure",
          "file": "src/handlers/ExceptionMapper.java",
          "start_line": 321,
          "description": "Potential info disclosure vulnerability in ExceptionMapper.java",
          "resolution": "",
          "code_churn": 1
        }
      ]
    },
    {
      "target_repo": "https://github.com/acme-corp/web-platform",
      "fork_url": "https://github.com/acme-corp-forks/web-platform",
      "run_number": 3,
      "run_id": "33836224944",
      "run_url": "https://github.com/acme-corp/codeql-devin-fixer/actions/runs/79857886275",
      "run_label": "run-3-2025-11-14-164700",
      "timestamp": "2025-11-14T16:47:00+00:00",
      "issues_found": 2,
      "severity_breakdown": {
        "critical": 1,
        "low": 1
      },
      "category_breakdown": {
        "auth-bypass": 1,
        "xss": 1
      },
      "batches_created": 1,
      "sessions": [
        {
          "session_id": "devin-54b58a7a5e4d47fba639e17d3a7cf36a",
          "session_url": "https://app.devin.ai/sessions/54b58a7a5e4d47fba639e17d3a7cf36a",
          "batch_id": 1,
          "status": "stopped",
          "issue_ids": [
            "ISSUE-003-001",
            "ISSUE-003-002"
          ],
          "pr_url": ""
        }
      ],
      "issue_fingerprints": [
        {
          "id": "ISSUE-003-001",
          "fingerprint": "e3c33a863200acf3548837e7c38e42d5",
          "rule_id": "js/missing-auth-check",
          "severity_tier": "critical",
          "cwe_family": "auth-bypass",
          "file": "src/middleware/auth.py",
          "start_line": 39,
          "description": "Potential auth bypass vulnerability in auth.py",
          "resolution": "",
          "code_churn": 1
        },
        {
          "id": "ISSUE-003-002",
          "fingerprint": "5574d6d803cf2cdff148939ef2c1edd0",
          "rule_id": "js/xss",
          "severity_tier": "low",
          "cwe_family": "xss",
          "file": "src/views/dashboard.js",
          "start_line": 259,
          "description": "Potential xss vulnerability in dashboard.js",
          "resolution": "",
          "code_churn": 0
        }
      ]
    },
    {
      "target_repo": "https://github.com/acme-corp/web-platform",
      "fork_url": "https://github.com/acme-corp-forks/web-platform",
      "run_number": 4,
      "run_id": "76899319619",
      "run_url": "https://github.com/acme-corp/codeql-devin-fixer/actions/runs/37518113010",
      "run_label": "run-4-2025-12-02-090800",
      "timestamp": "2025-12-02T09:08:00+00:00",
      "issues_found": 5,
      "severity_breakdown": {
        "medium": 3,
        "high": 1,
        "low": 1
      },
      "category_breakdown": {
        "crypto": 2,
        "insecure-deserialization": 1,
        "injection": 1,
        "xss": 1
      },
      "batches_created": 2,
      "sessions": [
        {
          "session_id": "devin-f83e2e4fc5644e708c852496dd83c469",
          "session_url": "https://app.devin.ai/sessions/f83e2e4fc5644e708c852496dd83c469",
          "batch_id": 1,
          "status": "finished",
          "issue_ids": [
            "ISSUE-004-001",
            "ISSUE-004-002"
          ],
          "pr_url": ""
        },
        {
          "session_id": "devin-1bee98ed71ae4fda8bd91310ecf6d964",
          "session_url": "https://app.devin.ai/sessions/1bee98ed71ae4fda8bd91310ecf6d964",
          "batch_id": 2,
          "status": "stopped",
          "issue_ids": [
            "ISSUE-004-003",
            "ISSUE-004-004"
          ],
          "pr_url": ""
        }
      ],
      "issue_fingerprints": [
        {
          "id": "ISSUE-004-001",
          "fingerprint": "83ed8028a79639cf4cd3d87f8426a977",
          "rule_id": "java/weak-crypto",
          "severity_tier": "medium",
          "cwe_family": "crypto",
          "file": "src/utils/encryption.js",
          "start_line": 214,
          "description": "Potential crypto vulnerability in encryption.js",
          "resolution": "",
          "code_churn": 2
        },
        {
          "id": "ISSUE-004-002",
          "fingerprint": "e65745e0d6e6b46d3240e3b6c9c5d1d5",
          "rule_id": "py/unsafe-deserialization",
          "severity_tier": "medium",
          "cwe_family": "insecure-deserialization",
          "file": "src/api/import_handler.py",
          "start_line": 126,
          "description": "Potential insecure deserialization vulnerability in import_handler.py",
          "resolution": "",
          "code_churn": 0
        },
        {
          "id": "ISSUE-004-003",
          "fingerprint": "37210f5aa7578de8f2ac7a2ed5d75608",
          "rule_id": "java/weak-crypto",
          "severity_tier": "high",
          "cwe_family": "crypto",
          "file": "src/auth/token_manager.py",
          "start_line": 15,
          "description": "Potential crypto vulnerability in token_manager.py",
          "resolution": "",
          "code_churn": 0
        },
        {
          "id": "ISSUE-004-004",
          "fingerprint": "e681f4f52d7691036d9626bcda4e4832",
          "rule_id": "py/sql-injection",
          "severity_tier": "medium",
          "cwe_family": "injection",
          "file": "src/api/controllers/users.py",
          "start_line": 476,
          "description": "Potential injection vulnerability in users.py",
          "resolution": "",
          "code_churn": 0
        },
        {
          "id": "ISSUE-004-005",
          "fingerprint": "5c61531429a8050af797f536dbd018a4",
          "rule_id": "js/stored-xss",
          "severity_tier": "low",
          "cwe_family": "xss",
          "file": "src/views/components/UserProfile.jsx",
          "start_line": 156,
          "description": "Potential xss vulnerability in UserProfile.jsx",
          "resolution": "",
          "code_churn": 3
        }
      ]
    },
    {
      "target_repo": "https://github.com/acme-corp/web-platform",
      "fork_url": "https://github.com/acme-corp-forks/web-platform",
      "run_number": 5,
      "run_id": "29106649725",
      "run_url": "https://github.com/acme-corp/codeql-devin-fixer/actions/runs/33286804321",
      "run_label": "run-5-2025-12-24-092800",
      "timestamp": "2025-12-24T09:28:00+00:00",
      "issues_found": 1,
      "severity_breakdown": {
        "medium": 1
      },
      "category_breakdown": {
        "xss": 1
      },
      "batches_created": 1,
      "sessions": [
        {
          "session_id": "devin-15b7ef03472246b9aac2e091909c39c5",
          "session_url": "https://app.devin.ai/sessions/15b7ef03472246b9aac2e091909c39c5",
          "batch_id": 1,
          "status": "finished",
          "issue_ids": [
            "ISSUE-005-001"
          ],
          "pr_url": "https://github.com/acme-corp-forks/web-platform/pull/3"
        }
      ],
      "issue_fingerprints": [
        {
          "id": "ISSUE-005-001",
          "fingerprint": "3aaf795b22bb93d436abc6f07ebef9ca",
          "rule_id": "js/xss",
          "severity_tier": "medium",
          "cwe_family": "xss",
          "file": "src/templates/comment.html",
          "start_line": 382,
          "description": "Potential xss vulnerability in comment.html",
          "resolution": "",
          "code_churn": 2
        }
      ]
    },
    {
      "target_repo": "https://github.com/acme-corp/web-platform",
      "fork_url": "https://github.com/acme-corp-forks/web-platform",
      "run_number": 6,
      "run_id": "13590711152",
      "run_url": "https://github.com/acme-corp/codeql-devin-fixer/actions/runs/22751741827",
      "run_label": "run-6-2025-12-25-060100",
      "timestamp": "2025-12-25T06:01:00+00:00",
      "issues_found": 1,
      "severity_breakdown": {
        "low": 1
      },
      "category_breakdown": {
        "xss": 1
      },
      "batches_created": 1,
      "sessions": [
        {
          "session_id": "devin-a4c2eb682d964416a37e8799140770a9",
          "session_url": "https://app.devin.ai/sessions/a4c2eb682d964416a37e8799140770a9",
          "batch_id": 1,
          "status": "error",
          "issue_ids": [
            "ISSUE-006-001"
          ],
          "pr_url": ""
        }
      ],
      "issue_fingerprints": [
        {
          "id": "ISSUE-006-001",
          "fingerprint": "bf6b31f887df3606ea50ec111f8db260",
          "rule_id": "js/reflected-xss",
          "severity_tier": "low",
          "cwe_family": "xss",
          "file": "src/views/dashboard.js",
          "start_line": 60,
          "description": "Potential xss vulnerability in dashboard.js",
          "resolution": "",
          "code_churn": 0
        }
      ]
    },
    {
      "target_repo": "https://github.com/acme-corp/web-platform",
      "fork_url": "https://github.com/acme-corp-forks/web-platform",
      "run_number": 7,
      "run_id": "50608951738",
      "run_url": "https://github.com/acme-corp/codeql-devin-fixer/actions/runs/77510049482",
      "run_label": "run-7-2026-01-04-150100",
      "timestamp": "2026-01-04T15:01:00+00:00",
      "issues_found": 1,
      "severity_breakdown": {
        "medium": 1
      },
      "category_breakdown": {
        "crypto": 1
      },
      "batches_created": 1,
      "sessions": [
        {
          "session_id": "devin-d51a37d524c348589ec32f16a24c1569",
          "session_url": "https://app.devin.ai/sessions/d51a37d524c348589ec32f16a24c1569",
          "batch_id": 1,
          "status": "error",
          "issue_ids": [
            "ISSUE-007-001"
          ],
          "pr_url": ""
        }
      ],
      "issue_fingerprints": [
        {
          "id": "ISSUE-007-001",
          "fingerprint": "90fb50e32c98706f3f81df1bacb287f7",
          "rule_id": "js/weak-crypto",
          "severity_tier": "medium",
          "cwe_family": "crypto",
          "file": "src/auth/token_manager.py",
          "start_line": 94,
          "description": "Potential crypto vulnerability in token_manager.py",
          "resolution": "",
          "code_churn": 3
        }
      ]
    },
    {
      "target_repo": "https://github.com/acme-corp/web-platform",
      "fork_url": "https://github.com/acme-corp-forks/web-platform",
      "run_number": 8,
      "run_id": "33756005883",
      "run_url": "https://github.com/acme-corp/codeql-devin-fixer/actions/runs/20771041378",
      "run_label": "run-8-2026-01-09-073700",
      "timestamp": "2026-01-09T07:37:00+00:00",
      "issues_found": 1,
      "severity_breakdown": {
        "high": 1
      },
      "category_breakdown": {
        "injection": 1
      },
      "batches_created": 1,
      "sessions": [
        {
          "session_id": "devin-a69f4f816c054deeb3e911e3935d09fe",
          "session_url": "https://app.devin.ai/sessions/a69f4f816c054deeb3e911e3935d09fe",
          "batch_id": 1,
          "status": "finished",
          "issue_ids": [
            "ISSUE-008-001"
          ],
          "pr_url": ""
        }
      ],
      "issue_fingerprints": [
        {
          "id": "ISSUE-008-001",
          "fingerprint": "2037ea67355b88012c4efcc3bbcd1f1d",
          "rule_id": "js/sql-injection",
          "severity_tier": "high",
          "cwe_family": "injection",
          "file": "src/services/QueryBuilder.java",
          "start_line": 39,
          "description": "Potential injection vulnerability in QueryBuilder.java",
          "resolution": "",
          "code_churn": 0
        }
      ]
    },
    {
      "target_repo": "https://github.com/acme-corp/web-platform",
      "fork_url": "https://github.com/acme-corp-forks/web-platform",
      "run_number": 9,
      "run_id": "89816264716",
      "run_url": "https://github.com/acme-corp/codeql-devin-fixer/actions/runs/55195007637",
      "run_label": "run-9-2026-01-11-094500",
      "timestamp": "2026-01-11T09:45:00+00:00",
      "issues_found": 1,
      "severity_breakdown": {
        "high": 1
      },
      "category_breakdown": {
        "crypto": 1
      },
      "batches_created": 1,
      "sessions": [
        {
          "session_id": "devin-9df39e5c3ec545369df27a5af9d282ac",
          "session_url": "https://app.devin.ai/sessions/9df39e5c3ec545369df27a5af9d282ac",
          "batch_id": 1,
          "status": "finished",
          "issue_ids": [
            "ISSUE-009-001"
          ],
          "pr_url": "https://github.com/acme-corp-forks/web-platform/pull/4"
        }
      ],
      "issue_fingerprints": [
        {
          "id": "ISSUE-009-001",
          "fingerprint": "7a495a1de3f07a450bfdd5049916892b",
          "rule_id": "js/weak-crypto",
          "severity_tier": "high",
          "cwe_family": "crypto",
          "file": "src/auth/token_manager.py",
          "start_line": 492,
          "description": "Potential crypto vulnerability in token_manager.py",
          "resolution": "",
          "code_churn": 1
        }
      ]
    },
    {
      "target_repo": "https://github.com/acme-corp/web-platform",
      "fork_url": "https://github.com/acme-corp-forks/web-platform",
      "run_number": 10,
      "run_id": "10311570307",
      "run_url": "https://github.com/acme-corp/codeql-devin-fixer/actions/runs/93572699943",
      "run_label": "run-10-2026-01-23-173400",
      "timestamp": "2026-01-23T17:34:00+00:00",
      "issues_found": 1,
      "severity_breakdown": {
        "low": 1
      },
      "category_breakdown": {
        "crypto": 1
      },
      "batches_created": 1,
      "sessions": [
        {
          "session_id": "devin-893593661f6e42d388d9fe473574bf55",
          "session_url": "https://app.devin.ai/sessions/893593661f6e42d388d9fe473574bf55",
          "batch_id": 1,
          "status": "finished",
          "issue_ids": [
            "ISSUE-010-001"
          ],
          "pr_url": "https://github.com/acme-corp-forks/web-platform/pull/5"
        }
      ],
      "issue_fingerprints": [
        {
          "id": "ISSUE-010-001",
          "fingerprint": "47069e94093092ee8931516bab5a3eeb",
          "rule_id": "js/weak-crypto",
          "severity_tier": "low",
          "cwe_family": "crypto",
          "file": "src/utils/encryption.js",
          "start_line": 77,
          "description": "Potential crypto vulnerability in encryption.js",
          "resolution": "",
          "code_churn": 2
        }
      ]
    },
    {
      "target_repo": "https://github.com/acme-corp/api-gateway",
      "fork_url": "https://github.com/acme-corp-forks/api-gateway",
      "run_number": 11,
      "run_id": "58090899706",
      "run_url": "https://github.com/acme-corp/codeql-devin-fixer/actions/runs/20442342819",
      "run_label": "run-11-2025-11-10-141300",
      "timestamp": "2025-11-10T14:13:00+00:00",
      "issues_found": 18,
      "severity_breakdown": {
        "critical": 2,
        "high": 8,
        "low": 2,
        "medium": 6
      },
      "category_breakdown": {
        "info-disclosure": 5,
        "xss": 2,
        "crypto": 2,
        "injection": 3,
        "auth-bypass": 4,
        "path-traversal": 1,
        "ssrf": 1
      },
      "batches_created": 4,
      "sessions": [
        {
          "session_id": "devin-935ef7725ad24eaa85510b2cf5f13ba4",
          "session_url": "https://app.devin.ai/sessions/935ef7725ad24eaa85510b2cf5f13ba4",
          "batch_id": 1,
          "status": "finished",
          "issue_ids": [
            "ISSUE-001-001",
            "ISSUE-001-002",
            "ISSUE-001-003",
            "ISSUE-001-004"
          ],
          "pr_url": "https://github.com/acme-corp-forks/api-gateway/pull/6"
        },
        {
          "session_id": "devin-3de4783341ab48de9a30845bbc3500a5",
          "session_url": "https://app.devin.ai/sessions/3de4783341ab48de9a30845bbc3500a5",
          "batch_id": 2,
          "status": "stopped",
          "issue_ids": [
            "ISSUE-001-005",
            "ISSUE-001-006",
            "ISSUE-001-007",
            "ISSUE-001-008"
          ],
          "pr_url": ""
        },
        {
          "session_id": "devin-a439fe6dd3e942149ade722cfeda7cdc",
          "session_url": "https://app.devin.ai/sessions/a439fe6dd3e942149ade722cfeda7cdc",
          "batch_id": 3,
          "status": "error",
          "issue_ids": [
            "ISSUE-001-009",
            "ISSUE-001-010",
            "ISSUE-001-011",
            "ISSUE-001-012"
          ],
          "pr_url": ""
        },
        {
          "session_id": "devin-378f2ee83d114aee9ed42d60938e1a92",
          "session_url": "https://app.devin.ai/sessions/378f2ee83d114aee9ed42d60938e1a92",
          "batch_id": 4,
          "status": "stopped",
          "issue_ids": [
            "ISSUE-001-013",
            "ISSUE-001-014",
            "ISSUE-001-015",
            "ISSUE-001-016"
          ],
          "pr_url": ""
        }
      ],
      "issue_fingerprints": [
        {
          "id": "ISSUE-001-001",
          "fingerprint": "e8dc1a38420e6a56836ac276f6f7149f",
          "rule_id": "java/information-exposure",
          "severity_tier": "critical",
          "cwe_family": "info-disclosure",
          "file": "src/middleware/error_handler.py",
          "start_line": 490,
          "description": "Potential info disclosure vulnerability in error_handler.py",
          "resolution": "",
          "code_churn": 1
        },
        {
          "id": "ISSUE-001-002",
          "fingerprint": "f22cee3056defe974a8c19d441e56c4f",
          "rule_id": "js/stored-xss",
          "severity_tier": "high",
          "cwe_family": "xss",
          "file": "src/views/dashboard.js",
          "start_line": 90,
          "description": "Potential xss vulnerability in dashboard.js",
          "resolution": "",
          "code_churn": 2
        },
        {
          "id": "ISSUE-001-003",
          "fingerprint": "39cbb93a4c618e0d3246dff5548b3e84",
          "rule_id": "java/weak-crypto",
          "severity_tier": "high",
          "cwe_family": "crypto",
          "file": "src/utils/encryption.js",
          "start_line": 116,
          "description": "Potential crypto vulnerability in encryption.js",
          "resolution": "",
          "code_churn": 2
        },
        {
          "id": "ISSUE-001-004",
          "fingerprint": "b4c2f98e48dc06f5a9824220df23c963",
          "rule_id": "py/stack-trace-exposure",
          "severity_tier": "high",
          "cwe_family": "info-disclosure",
          "file": "src/middleware/error_handler.py",
          "start_line": 337,
          "description": "Potential info disclosure vulnerability in error_handler.py",
          "resolution": "",
          "code_churn": 3
        },
        {
          "id": "ISSUE-001-005",
          "fingerprint": "11ab229970e8244fc93793b3c7e81764",
          "rule_id": "js/sql-injection",
          "severity_tier": "low",
          "cwe_family": "injection",
          "file": "src/services/QueryBuilder.java",
          "start_line": 408,
          "description": "Potential injection vulnerability in QueryBuilder.java",
          "resolution": "",
          "code_churn": 1
        },
        {
          "id": "ISSUE-001-006",
          "fingerprint": "c4044e59fa7d1ef164a08e14287ee345",
          "rule_id": "py/stack-trace-exposure",
          "severity_tier": "medium",
          "cwe_family": "info-disclosure",
          "file": "src/handlers/ExceptionMapper.java",
          "start_line": 241,
          "description": "Potential info disclosure vulnerability in ExceptionMapper.java",
          "resolution": "",
          "code_churn": 3
        },
        {
          "id": "ISSUE-001-007",
          "fingerprint": "587cca0a466ff15944b1697da526ab4e",
          "rule_id": "js/xss",
          "severity_tier": "medium",
          "cwe_family": "xss",
          "file": "src/views/dashboard.js",
          "start_line": 478,
          "description": "Potential xss vulnerability in dashboard.js",
          "resolution": "",
          "code_churn": 1
        },
        {
          "id": "ISSUE-001-008",
          "fingerprint": "27b21b655caf0a35e18c20575f14a993",
          "rule_id": "py/insecure-auth",
          "severity_tier": "medium",
          "cwe_family": "auth-bypass",
          "file": "src/api/middleware/auth.js",
          "start_line": 82,
          "description": "Potential auth bypass vulnerability in auth.js",
          "resolution": "",
          "code_churn": 0
        },
        {
          "id": "ISSUE-001-009",
          "fingerprint": "35273d7483286f7176018cbdd4e05c91",
          "rule_id": "java/sql-injection",
          "severity_tier": "high",
          "cwe_family": "injection",
          "file": "src/api/controllers/search.js",
          "start_line": 367,
          "description": "Potential injection vulnerability in search.js",
          "resolution": "",
          "code_churn": 1
        },
        {
          "id": "ISSUE-001-010",
          "fingerprint": "a64ee86c4e4ae2d9da3bbc73c164c8d7",
          "rule_id": "js/missing-auth-check",
          "severity_tier": "medium",
          "cwe_family": "auth-bypass",
          "file": "src/middleware/auth.py",
          "start_line": 492,
          "description": "Potential auth bypass vulnerability in auth.py",
          "resolution": "",
          "code_churn": 1
        },
        {
          "id": "ISSUE-001-011",
          "fingerprint": "e2f96c8da1eeb70a21df51ea36ee9b49",
          "rule_id": "py/path-injection",
          "severity_tier": "low",
          "cwe_family": "path-traversal",
          "file": "src/utils/file_handler.py",
          "start_line": 111,
          "description": "Potential path traversal vulnerability in file_handler.py",
          "resolution": "",
          "code_churn": 2
        },
        {
          "id": "ISSUE-001-012",
          "fingerprint": "30288ce382566b072836342fad826267",
          "rule_id": "py/ssrf",
          "severity_tier": "medium",
          "cwe_family": "ssrf",
          "file": "src/services/WebhookClient.java",
          "start_line": 102,
          "description": "Potential ssrf vulnerability in WebhookClient.java",
          "resolution": "",
          "code_churn": 0
        },
        {
          "id": "ISSUE-001-013",
          "fingerprint": "cce0cc1822ead1186e54277ec219bd0f",
          "rule_id": "py/command-injection",
          "severity_tier": "high",
          "cwe_family": "injection",
          "file": "src/api/controllers/search.js",
          "start_line": 124,
          "description": "Potential injection vulnerability in search.js",
          "resolution": "",
          "code_churn": 3
        },
        {
          "id": "ISSUE-001-014",
          "fingerprint": "18895817379bfeb4d55dba0c224623ad",
          "rule_id": "py/weak-crypto",
          "severity_tier": "high",
          "cwe_family": "crypto",
          "file": "src/auth/token_manager.py",
          "start_line": 360,
          "description": "Potential crypto vulnerability in token_manager.py",
          "resolution": "",
          "code_churn": 1
        },
        {
          "id": "ISSUE-001-015",
          "fingerprint": "67b2e2dbc0706e4ef26338fb1b9e67a0",
          "rule_id": "py/stack-trace-exposure",
          "severity_tier": "high",
          "cwe_family": "info-disclosure",
          "file": "src/api/error_boundary.js",
          "start_line": 203,
          "description": "Potential info disclosure vulnerability in error_boundary.js",
          "resolution": "",
          "code_churn": 3
        },
        {
          "id": "ISSUE-001-016",
          "fingerprint": "c3bf91afed7b823e5eeb8d54d47c4973",
          "rule_id": "py/insecure-auth",
          "severity_tier": "medium",
          "cwe_family": "auth-bypass",
          "file": "src/middleware/auth.py",
          "start_line": 474,
          "description": "Potential auth bypass vulnerability in auth.py",
          "resolution": "",
          "code_churn": 2
        },
        {
          "id": "ISSUE-001-017",
          "fingerprint": "6171ffad0a0bf85001c25c9d0c598c44",
          "rule_id": "py/stack-trace-exposure",
          "severity_tier": "critical",
          "cwe_family": "info-disclosure",
          "file": "src/middleware/error_handler.py",
          "start_line": 331,
          "description": "Potential info disclosure vulnerability in error_handler.py",
          "resolution": "",
          "code_churn": 3
        },
        {
          "id": "ISSUE-001-018",
          "fingerprint": "40eb43e0557de8ade5f2c958781a2807",
          "rule_id": "js/missing-auth-check",
          "severity_tier": "high",
          "cwe_family": "auth-bypass",
          "file": "src/middleware/auth.py",
          "start_line": 224,
          "description": "Potential auth bypass vulnerability in auth.py",
          "resolution": "",
          "code_churn": 1
        }
      ]
    },
    {
      "target_repo": "https://github.com/acme-corp/api-gateway",
      "fork_url": "https://github.com/acme-corp-forks/api-gateway",
      "run_number": 12,
      "run_id": "93645073667",
      "run_url": "https://github.com/acme-corp/codeql-devin-fixer/actions/runs/70442337008",
      "run_label": "run-12-2025-11-21-135300",
      "timestamp": "2025-11-21T13:53:00+00:00",
      "issues_found": 3,
      "severity_breakdown": {
        "high": 1,
        "medium": 1,
        "critical": 1
      },
      "category_breakdown": {
        "auth-bypass": 1,
        "path-traversal": 1,
        "crypto": 1
      },
      "batches_created": 1,
      "sessions": [
        {
          "session_id": "devin-e16017965e8b4462b182d9cc74877071",
          "session_url": "https://app.devin.ai/sessions/e16017965e8b4462b182d9cc74877071",
          "batch_id": 1,
          "status": "finished",
          "issue_ids": [
            "ISSUE-002-001",
            "ISSUE-002-002",
            "ISSUE-002-003"
          ],
          "pr_url": "https://github.com/acme-corp-forks/api-gateway/pull/7"
        }
      ],
      "issue_fingerprints": [
        {
          "id": "ISSUE-002-001",
          "fingerprint": "7cd627d785963abc7f23d9eda466b283",
          "rule_id": "js/missing-auth-check",
          "severity_tier": "high",
          "cwe_family": "auth-bypass",
          "file": "src/api/middleware/auth.js",
          "start_line": 236,
          "description": "Potential auth bypass vulnerability in auth.js",
          "resolution": "",
          "code_churn": 1
        },
        {
          "id": "ISSUE-002-002",
          "fingerprint": "39c4a16f0917f1c66e67d1f4ed16a8ce",
          "rule_id": "java/path-injection",
          "severity_tier": "medium",
          "cwe_family": "path-traversal",
          "file": "src/utils/file_handler.py",
          "start_line": 156,
          "description": "Potential path traversal vulnerability in file_handler.py",
          "resolution": "",
          "code_churn": 2
        },
        {
          "id": "ISSUE-002-003",
          "fingerprint": "47498cc82addcd9f1fa6af6f16ddf84f",
          "rule_id": "java/weak-crypto",
          "severity_tier": "critical",
          "cwe_family": "crypto",
          "file": "src/utils/encryption.js",
          "start_line": 127,
          "description": "Potential crypto vulnerability in encryption.js",
          "resolution": "",
          "code_churn": 1
        }
      ]
    },
    {
      "target_repo": "https://github.com/acme-corp/api-gateway",
      "fork_url": "https://github.com/acme-corp-forks/api-gateway",
      "run_number": 13,
      "run_id": "93505217012",
      "run_url": "https://github.com/acme-corp/codeql-devin-fixer/actions/runs/82550674734",
      "run_label": "run-13-2025-12-02-111800",
      "timestamp": "2025-12-02T11:18:00+00:00",
      "issues_found": 3,
      "severity_breakdown": {
        "high": 1,
        "low": 1,
        "critical": 1
      },
      "category_breakdown": {
        "ssrf": 1,
        "xss": 1,
        "crypto": 1
      },
      "batches_created": 1,
      "sessions": [
        {
          "session_id": "devin-10952715826b44e582cb76ecb0990fe9",
          "session_url": "https://app.devin.ai/sessions/10952715826b44e582cb76ecb0990fe9",
          "batch_id": 1,
          "status": "finished",
          "issue_ids": [
            "ISSUE-003-001",
            "ISSUE-003-002",
            "ISSUE-003-003"
          ],
          "pr_url": "https://github.com/acme-corp-forks/api-gateway/pull/8"
        }
      ],
      "issue_fingerprints": [
        {
          "id": "ISSUE-003-001",
          "fingerprint": "48afb12dd3d40b4d26d3216d8480af89",
          "rule_id": "py/ssrf",
          "severity_tier": "high",
          "cwe_family": "ssrf",
          "file": "src/services/webhook_sender.py",
          "start_line": 345,
          "description": "Potential ssrf vulnerability in webhook_sender.py",
          "resolution": "",
          "code_churn": 0
        },
        {
          "id": "ISSUE-003-002",
          "fingerprint": "76bd15d3b9dc5280467d90bce303c6e9",
          "rule_id": "js/reflected-xss",
          "severity_tier": "low",
          "cwe_family": "xss",
          "file": "src/views/components/UserProfile.jsx",
          "start_line": 101,
          "description": "Potential xss vulnerability in UserProfile.jsx",
          "resolution": "",
          "code_churn": 3
        },
        {
          "id": "ISSUE-003-003",
          "fingerprint": "299d37bd39bc172ea59b4ddf73178e63",
          "rule_id": "py/weak-crypto",
          "severity_tier": "critical",
          "cwe_family": "crypto",
          "file": "src/utils/encryption.js",
          "start_line": 80,
          "description": "Potential crypto vulnerability in encryption.js",
          "resolution": "",
          "code_churn": 3
        }
      ]
    },
    {
      "target_repo": "https://github.com/acme-corp/api-gateway",
      "fork_url": "https://github.com/acme-corp-forks/api-gateway",
      "run_number": 14,
      "run_id": "67616418900",
      "run_url": "https://github.com/acme-corp/codeql-devin-fixer/actions/runs/84435568770",
      "run_label": "run-14-2025-12-15-075600",
      "timestamp": "2025-12-15T07:56:00+00:00",
      "issues_found": 4,
      "severity_breakdown": {
        "low": 2,
        "high": 2
      },
      "category_breakdown": {
        "insecure-deserialization": 1,
        "info-disclosure": 1,
        "xss": 2
      },
      "batches_created": 1,
      "sessions": [
        {
          "session_id": "devin-8cc80e7803a0434ea6397e07fb13122d",
          "session_url": "https://app.devin.ai/sessions/8cc80e7803a0434ea6397e07fb13122d",
          "batch_id": 1,
          "status": "finished",
          "issue_ids": [
            "ISSUE-004-001",
            "ISSUE-004-002",
            "ISSUE-004-003",
            "ISSUE-004-004"
          ],
          "pr_url": "https://github.com/acme-corp-forks/api-gateway/pull/9"
        }
      ],
      "issue_fingerprints": [
        {
          "id": "ISSUE-004-001",
          "fingerprint": "7a9d08ad6f489dd787bd5ca4be28df5f",
          "rule_id": "java/unsafe-deserialization",
          "severity_tier": "low",
          "cwe_family": "insecure-deserialization",
          "file": "src/services/DataImporter.java",
          "start_line": 394,
          "description": "Potential insecure deserialization vulnerability in DataImporter.java",
          "resolution": "",
          "code_churn": 1
        },
        {
          "id": "ISSUE-004-002",
          "fingerprint": "f650c53bf62491f06f3217102ca384a3",
          "rule_id": "java/information-exposure",
          "severity_tier": "low",
          "cwe_family": "info-disclosure",
          "file": "src/api/error_boundary.js",
          "start_line": 331,
          "description": "Potential info disclosure vulnerability in error_boundary.js",
          "resolution": "",
          "code_churn": 1
        },
        {
          "id": "ISSUE-004-003",
          "fingerprint": "174737909fd56b3f07224b4f4e74e827",
          "rule_id": "js/stored-xss",
          "severity_tier": "high",
          "cwe_family": "xss",
          "file": "src/templates/comment.html",
          "start_line": 132,
          "description": "Potential xss vulnerability in comment.html",
          "resolution": "",
          "code_churn": 2
        },
        {
          "id": "ISSUE-004-004",
          "fingerprint": "209cdc93c9d402b22d79ad2864a6a5b7",
          "rule_id": "js/xss",
          "severity_tier": "high",
          "cwe_family": "xss",
          "file": "src/views/components/UserProfile.jsx",
          "start_line": 131,
          "description": "Potential xss vulnerability in UserProfile.jsx",
          "resolution": "",
          "code_churn": 3
        }
      ]
    },
    {
      "target_repo": "https://github.com/acme-corp/api-gateway",
      "fork_url": "https://github.com/acme-corp-forks/api-gateway",
      "run_number": 15,
      "run_id": "84814126733",
      "run_url": "https://github.com/acme-corp/codeql-devin-fixer/actions/runs/75371715916",
      "run_label": "run-15-2026-01-04-100800",
      "timestamp": "2026-01-04T10:08:00+00:00",
      "issues_found": 1,
      "severity_breakdown": {
        "medium": 1
      },
      "category_breakdown": {
        "injection": 1
      },
      "batches_created": 1,
      "sessions": [
        {
          "session_id": "devin-0010381c6c884501b736a66257c4bf3e",
          "session_url": "https://app.devin.ai/sessions/0010381c6c884501b736a66257c4bf3e",
          "batch_id": 1,
          "status": "finished",
          "issue_ids": [
            "ISSUE-005-001"
          ],
          "pr_url": ""
        }
      ],
      "issue_fingerprints": [
        {
          "id": "ISSUE-005-001",
          "fingerprint": "22a64ac91cb5a8508d5d53fe9f1df460",
          "rule_id": "py/command-injection",
          "severity_tier": "medium",
          "cwe_family": "injection",
          "file": "src/db/queries.py",
          "start_line": 13,
          "description": "Potential injection vulnerability in queries.py",
          "resolution": "",
          "code_churn": 2
        }
      ]
    },
    {
      "target_repo": "https://github.com/acme-corp/api-gateway",
      "fork_url": "https://github.com/acme-corp-forks/api-gateway",
      "run_number": 16,
      "run_id": "95816547455",
      "run_url": "https://github.com/acme-corp/codeql-devin-fixer/actions/runs/12294043548",
      "run_label": "run-16-2026-01-09-171900",
      "timestamp": "2026-01-09T17:19:00+00:00",
      "issues_found": 1,
      "severity_breakdown": {
        "medium": 1
      },
      "category_breakdown": {
        "ssrf": 1
      },
      "batches_created": 1,
      "sessions": [
        {
          "session_id": "devin-f47947c207284669b16e3f1efabce5a8",
          "session_url": "https://app.devin.ai/sessions/f47947c207284669b16e3f1efabce5a8",
          "batch_id": 1,
          "status": "stopped",
          "issue_ids": [
            "ISSUE-006-001"
          ],
          "pr_url": ""
        }
      ],
      "issue_fingerprints": [
        {
          "id": "ISSUE-006-001",
          "fingerprint": "3093f8a4a0dae05e8c8ebb94e0527043",
          "rule_id": "java/ssrf",
          "severity_tier": "medium",
          "cwe_family": "ssrf",
          "file": "src/services/WebhookClient.java",
          "start_line": 380,
          "description": "Potential ssrf vulnerability in WebhookClient.java",
          "resolution": "",
          "code_churn": 1
        }
      ]
    },
    {
      "target_repo": "https://github.com/acme-corp/api-gateway",
      "fork_url": "https://github.com/acme-corp-forks/api-gateway",
      "run_number": 17,
      "run_id": "46170345521",
      "run_url": "https://github.com/acme-corp/codeql-devin-fixer/actions/runs/22175849680",
      "run_label": "run-17-2026-01-18-184100",
      "timestamp": "2026-01-18T18:41:00+00:00",
      "issues_found": 2,
      "severity_breakdown": {
        "low": 1,
        "high": 1
      },
      "category_breakdown": {
        "xss": 1,
        "info-disclosure": 1
      },
      "batches_created": 1,
      "sessions": [
        {
          "session_id": "devin-985f036257684f1f848e055e62c1f965",
          "session_url": "https://app.devin.ai/sessions/985f036257684f1f848e055e62c1f965",
          "batch_id": 1,
          "status": "finished",
          "issue_ids": [
            "ISSUE-007-001",
            "ISSUE-007-002"
          ],
          "pr_url": "https://github.com/acme-corp-forks/api-gateway/pull/10"
        }
      ],
      "issue_fingerprints": [
        {
          "id": "ISSUE-007-001",
          "fingerprint": "dae6911fd8d15583b54ad9387ded49ae",
          "rule_id": "js/stored-xss",
          "severity_tier": "low",
          "cwe_family": "xss",
          "file": "src/templates/comment.html",
          "start_line": 79,
          "description": "Potential xss vulnerability in comment.html",
          "resolution": "",
          "code_churn": 3
        },
        {
          "id": "ISSUE-007-002",
          "fingerprint": "2c95309d96f3bad0fd31468bcec3472d",
          "rule_id": "js/information-exposure",
          "severity_tier": "high",
          "cwe_family": "info-disclosure",
          "file": "src/api/error_boundary.js",
          "start_line": 119,
          "description": "Potential info disclosure vulnerability in error_boundary.js",
          "resolution": "",
          "code_churn": 3
        }
      ]
    },
    {
      "target_repo": "https://github.com/acme-corp/mobile-backend",
      "fork_url": "https://github.com/acme-corp-forks/mobile-backend",
      "run_number": 18,
      "run_id": "18663993845",
      "run_url": "https://github.com/acme-corp/codeql-devin-fixer/actions/runs/41328503269",
      "run_label": "run-18-2025-11-03-150900",
      "timestamp": "2025-11-03T15:09:00+00:00",
      "issues_found": 12,
      "severity_breakdown": {
        "medium": 4,
        "low": 1,
        "critical": 3,
        "high": 4
      },
      "category_breakdown": {
        "xss": 1,
        "ssrf": 1,
        "info-disclosure": 4,
        "injection": 1,
        "auth-bypass": 2,
        "insecure-deserialization": 2,
        "crypto": 1
      },
      "batches_created": 3,
      "sessions": [
        {
          "session_id": "devin-a26d1ab12dda44d6a6260a1540a84c25",
          "session_url": "https://app.devin.ai/sessions/a26d1ab12dda44d6a6260a1540a84c25",
          "batch_id": 1,
          "status": "stopped",
          "issue_ids": [
            "ISSUE-001-001",
            "ISSUE-001-002",
            "ISSUE-001-003",
            "ISSUE-001-004"
          ],
          "pr_url": ""
        },
        {
          "session_id": "devin-03a63f5b78fa4951a494f592ecca75b5",
          "session_url": "https://app.devin.ai/sessions/03a63f5b78fa4951a494f592ecca75b5",
          "batch_id": 2,
          "status": "finished",
          "issue_ids": [
            "ISSUE-001-005",
            "ISSUE-001-006",
            "ISSUE-001-007",
            "ISSUE-001-008"
          ],
          "pr_url": "https://github.com/acme-corp-forks/mobile-backend/pull/11"
        },
        {
          "session_id": "devin-736d1924f1354448bf1070e2bc499f75",
          "session_url": "https://app.devin.ai/sessions/736d1924f1354448bf1070e2bc499f75",
          "batch_id": 3,
          "status": "stopped",
          "issue_ids": [
            "ISSUE-001-009",
            "ISSUE-001-010",
            "ISSUE-001-011",
            "ISSUE-001-012"
          ],
          "pr_url": ""
        }
      ],
      "issue_fingerprints": [
        {
          "id": "ISSUE-001-001",
          "fingerprint": "2d148ab896377736fcbb28102ca12cfb",
          "rule_id": "js/xss",
          "severity_tier": "medium",
          "cwe_family": "xss",
          "file": "src/templates/comment.html",
          "start_line": 65,
          "description": "Potential xss vulnerability in comment.html",
          "resolution": "",
          "code_churn": 0
        },
        {
          "id": "ISSUE-001-002",
          "fingerprint": "e0dbf632e2e05a2faeb4c7f18fdcaec1",
          "rule_id": "java/ssrf",
          "severity_tier": "low",
          "cwe_family": "ssrf",
          "file": "src/services/webhook_sender.py",
          "start_line": 49,
          "description": "Potential ssrf vulnerability in webhook_sender.py",
          "resolution": "",
          "code_churn": 1
        },
        {
          "id": "ISSUE-001-003",
          "fingerprint": "6fabe5be07b7c0f45d65975082162045",
          "rule_id": "java/information-exposure",
          "severity_tier": "critical",
          "cwe_family": "info-disclosure",
          "file": "src/handlers/ExceptionMapper.java",
          "start_line": 424,
          "description": "Potential info disclosure vulnerability in ExceptionMapper.java",
          "resolution": "",
          "code_churn": 0
        },
        {
          "id": "ISSUE-001-004",
          "fingerprint": "53892cfef58f68a534702c273cc0cefc",
          "rule_id": "java/sql-injection",
          "severity_tier": "medium",
          "cwe_family": "injection",
          "file": "src/db/queries.py",
          "start_line": 351,
          "description": "Potential injection vulnerability in queries.py",
          "resolution": "",
          "code_churn": 2
        },
        {
          "id": "ISSUE-001-005",
          "fingerprint": "dea71087819c4fd6013d1cc6cbdeeb6c",
          "rule_id": "py/insecure-auth",
          "severity_tier": "critical",
          "cwe_family": "auth-bypass",
          "file": "src/api/middleware/auth.js",
          "start_line": 435,
          "description": "Potential auth bypass vulnerability in auth.js",
          "resolution": "",
          "code_churn": 3
        },
        {
          "id": "ISSUE-001-006",
          "fingerprint": "ed52982086896ced6d631256d3f6ee5c",
          "rule_id": "js/missing-auth-check",
          "severity_tier": "critical",
          "cwe_family": "auth-bypass",
          "file": "src/middleware/auth.py",
          "start_line": 237,
          "description": "Potential auth bypass vulnerability in auth.py",
          "resolution": "",
          "code_churn": 1
        },
        {
          "id": "ISSUE-001-007",
          "fingerprint": "259eacac7abf7dd5f637e967ad7250c8",
          "rule_id": "java/information-exposure",
          "severity_tier": "medium",
          "cwe_family": "info-disclosure",
          "file": "src/handlers/ExceptionMapper.java",
          "start_line": 412,
          "description": "Potential info disclosure vulnerability in ExceptionMapper.java",
          "resolution": "",
          "code_churn": 3
        },
        {
          "id": "ISSUE-001-008",
          "fingerprint": "ed3676ef9074cb241e4a093979a4238a",
          "rule_id": "js/information-exposure",
          "severity_tier": "high",
          "cwe_family": "info-disclosure",
          "file": "src/middleware/error_handler.py",
          "start_line": 442,
          "description": "Potential info disclosure vulnerability in error_handler.py",
          "resolution": "",
          "code_churn": 0
        },
        {
          "id": "ISSUE-001-009",
          "fingerprint": "9a68871a18fab385f6877b0ce6643fcf",
          "rule_id": "py/unsafe-deserialization",
          "severity_tier": "high",
          "cwe_family": "insecure-deserialization",
          "file": "src/services/DataImporter.java",
          "start_line": 309,
          "description": "Potential insecure deserialization vulnerability in DataImporter.java",
          "resolution": "",
          "code_churn": 3
        },
        {
          "id": "ISSUE-001-010",
          "fingerprint": "8b66c3c79c476e91cc23c2be5d3dea04",
          "rule_id": "java/unsafe-deserialization",
          "severity_tier": "high",
          "cwe_family": "insecure-deserialization",
          "file": "src/api/import_handler.py",
          "start_line": 268,
          "description": "Potential insecure deserialization vulnerability in import_handler.py",
          "resolution": "",
          "code_churn": 1
        },
        {
          "id": "ISSUE-001-011",
          "fingerprint": "2dc1bcb318477aa582e2ef394bc2701b",
          "rule_id": "js/information-exposure",
          "severity_tier": "high",
          "cwe_family": "info-disclosure",
          "file": "src/api/error_boundary.js",
          "start_line": 470,
          "description": "Potential info disclosure vulnerability in error_boundary.js",
          "resolution": "",
          "code_churn": 2
        },
        {
          "id": "ISSUE-001-012",
          "fingerprint": "68ce6d94ed6c469be3c53b76f9a8ed46",
          "rule_id": "py/weak-crypto",
          "severity_tier": "medium",
          "cwe_family": "crypto",
          "file": "src/auth/token_manager.py",
          "start_line": 389,
          "description": "Potential crypto vulnerability in token_manager.py",
          "resolution": "",
          "code_churn": 3
        }
      ]
    },
    {
      "target_repo": "https://github.com/acme-corp/mobile-backend",
      "fork_url": "https://github.com/acme-corp-forks/mobile-backend",
      "run_number": 19,
      "run_id": "90421480195",
      "run_url": "https://github.com/acme-corp/codeql-devin-fixer/actions/runs/93857676819",
      "run_label": "run-19-2025-11-03-173400",
      "timestamp": "2025-11-03T17:34:00+00:00",
      "issues_found": 1,
      "severity_breakdown": {
        "high": 1
      },
      "category_breakdown": {
        "xss": 1
      },
      "batches_created": 1,
      "sessions": [
        {
          "session_id": "devin-2b68426fb17045cb881af7d51e15180d",
          "session_url": "https://app.devin.ai/sessions/2b68426fb17045cb881af7d51e15180d",
          "batch_id": 1,
          "status": "finished",
          "issue_ids": [
            "ISSUE-002-001"
          ],
          "pr_url": "https://github.com/acme-corp-forks/mobile-backend/pull/12"
        }
      ],
      "issue_fingerprints": [
        {
          "id": "ISSUE-002-001",
          "fingerprint": "cc2f235574a4439115a9f7c72acacd7c",
          "rule_id": "js/stored-xss",
          "severity_tier": "high",
          "cwe_family": "xss",
          "file": "src/views/dashboard.js",
          "start_line": 496,
          "description": "Potential xss vulnerability in dashboard.js",
          "resolution": "",
          "code_churn": 1
        }
      ]
    },
    {
      "target_repo": "https://github.com/acme-corp/mobile-backend",
      "fork_url": "https://github.com/acme-corp-forks/mobile-backend",
      "run_number": 20,
      "run_id": "32938157341",
      "run_url": "https://github.com/acme-corp/codeql-devin-fixer/actions/runs/18441748123",
      "run_label": "run-20-2025-11-04-091200",
      "timestamp": "2025-11-04T09:12:00+00:00",
      "issues_found": 3,
      "severity_breakdown": {
        "low": 1,
        "critical": 1,
        "medium": 1
      },
      "category_breakdown": {
        "info-disclosure": 1,
        "path-traversal": 2
      },
      "batches_created": 1,
      "sessions": [
        {
          "session_id": "devin-6e86ecc7e8014f659f08db54bb94ee07",
          "session_url": "https://app.devin.ai/sessions/6e86ecc7e8014f659f08db54bb94ee07",
          "batch_id": 1,
          "status": "finished",
          "issue_ids": [
            "ISSUE-003-001",
            "ISSUE-003-002",
            "ISSUE-003-003"
          ],
          "pr_url": "https://github.com/acme-corp-forks/mobile-backend/pull/13"
        }
      ],
      "issue_fingerprints": [
        {
          "id": "ISSUE-003-001",
          "fingerprint": "da5aa1ad40b2335938d68ed921dfadf1",
          "rule_id": "py/stack-trace-exposure",
          "severity_tier": "low",
          "cwe_family": "info-disclosure",
          "file": "src/api/error_boundary.js",
          "start_line": 101,
          "description": "Potential info disclosure vulnerability in error_boundary.js",
          "resolution": "",
          "code_churn": 2
        },
        {
          "id": "ISSUE-003-002",
          "fingerprint": "dd39af0efa5d22a7162d26aede0f8faf",
          "rule_id": "py/path-injection",
          "severity_tier": "critical",
          "cwe_family": "path-traversal",
          "file": "src/utils/file_handler.py",
          "start_line": 38,
          "description": "Potential path traversal vulnerability in file_handler.py",
          "resolution": "",
          "code_churn": 2
        },
        {
          "id": "ISSUE-003-003",
          "fingerprint": "1c2ab4adc8c20ecf9717eacad574c34d",
          "rule_id": "java/path-injection",
          "severity_tier": "medium",
          "cwe_family": "path-traversal",
          "file": "src/api/upload.js",
          "start_line": 64,
          "description": "Potential path traversal vulnerability in upload.js",
          "resolution": "",
          "code_churn": 0
        }
      ]
    },
    {
      "target_repo": "https://github.com/acme-corp/mobile-backend",
      "fork_url": "https://github.com/acme-corp-forks/mobile-backend",
      "run_number": 21,
      "run_id": "70086726736",
      "run_url": "https://github.com/acme-corp/codeql-devin-fixer/actions/runs/88621009477",
      "run_label": "run-21-2025-11-07-111400",
      "timestamp": "2025-11-07T11:14:00+00:00",
      "issues_found": 3,
      "severity_breakdown": {
        "high": 2,
        "medium": 1
      },
      "category_breakdown": {
        "xss": 1,
        "info-disclosure": 1,
        "crypto": 1
      },
      "batches_created": 1,
      "sessions": [
        {
          "session_id": "devin-dfd42428b7a64809944192741b48ae31",
          "session_url": "https://app.devin.ai/sessions/dfd42428b7a64809944192741b48ae31",
          "batch_id": 1,
          "status": "stopped",
          "issue_ids": [
            "ISSUE-004-001",
            "ISSUE-004-002",
            "ISSUE-004-003"
          ],
          "pr_url": ""
        }
      ],
      "issue_fingerprints": [
        {
          "id": "ISSUE-004-001",
          "fingerprint": "f74cecb22aa7e99a4e31b8a157f3e20a",
          "rule_id": "js/stored-xss",
          "severity_tier": "high",
          "cwe_family": "xss",
          "file": "src/views/dashboard.js",
          "start_line": 361,
          "description": "Potential xss vulnerability in dashboard.js",
          "resolution": "",
          "code_churn": 0
        },
        {
          "id": "ISSUE-004-002",
          "fingerprint": "ba9610cb6c5709b3fbe042f0affa2979",
          "rule_id": "py/stack-trace-exposure",
          "severity_tier": "high",
          "cwe_family": "info-disclosure",
          "file": "src/middleware/error_handler.py",
          "start_line": 71,
          "description": "Potential info disclosure vulnerability in error_handler.py",
          "resolution": "",
          "code_churn": 3
        },
        {
          "id": "ISSUE-004-003",
          "fingerprint": "e91549c2fcb3dd722794b73fa609aa8f",
          "rule_id": "java/weak-crypto",
          "severity_tier": "medium",
          "cwe_family": "crypto",
          "file": "src/utils/encryption.js",
          "start_line": 242,
          "description": "Potential crypto vulnerability in encryption.js",
          "resolution": "",
          "code_churn": 3
        }
      ]
    },
    {
      "target_repo": "https://github.com/acme-corp/mobile-backend",
      "fork_url": "https://github.com/acme-corp-forks/mobile-backend",
      "run_number": 22,
      "run_id": "99297729107",
      "run_url": "https://github.com/acme-corp/codeql-devin-fixer/actions/runs/66684201906",
      "run_label": "run-22-2025-11-28-134400",
      "timestamp": "2025-11-28T13:44:00+00:00",
      "issues_found": 3,
      "severity_breakdown": {
        "high": 2,
        "medium": 1
      },
      "category_breakdown": {
        "crypto": 1,
        "xss": 1,
        "insecure-deserialization": 1
      },
      "batches_created": 1,
      "sessions": [
        {
          "session_id": "devin-7884b76197264bfa95990f4edcb553f8",
          "session_url": "https://app.devin.ai/sessions/7884b76197264bfa95990f4edcb553f8",
          "batch_id": 1,
          "status": "finished",
          "issue_ids": [
            "ISSUE-005-001",
            "ISSUE-005-002",
            "ISSUE-005-003"
          ],
          "pr_url": ""
        }
      ],
      "issue_fingerprints": [
        {
          "id": "ISSUE-005-001",
          "fingerprint": "c924e4a655e70ff0559321a81db4846e",
          "rule_id": "js/weak-crypto",
          "severity_tier": "high",
          "cwe_family": "crypto",
          "file": "src/security/CryptoHelper.java",
          "start_line": 51,
          "description": "Potential crypto vulnerability in CryptoHelper.java",
          "resolution": "",
          "code_churn": 1
        },
        {
          "id": "ISSUE-005-002",
          "fingerprint": "be73a40e691fa046ce46748a45bbf3a6",
          "rule_id": "js/xss",
          "severity_tier": "high",
          "cwe_family": "xss",
          "file": "src/views/components/UserProfile.jsx",
          "start_line": 220,
          "description": "Potential xss vulnerability in UserProfile.jsx",
          "resolution": "",
          "code_churn": 3
        },
        {
          "id": "ISSUE-005-003",
          "fingerprint": "01964216dc5322ec11d62975339b5c01",
          "rule_id": "java/unsafe-deserialization",
          "severity_tier": "medium",
          "cwe_family": "insecure-deserialization",
          "file": "src/api/import_handler.py",
          "start_line": 130,
          "description": "Potential insecure deserialization vulnerability in import_handler.py",
          "resolution": "",
          "code_churn": 2
        }
      ]
    },
    {
      "target_repo": "https://github.com/acme-corp/mobile-backend",
      "fork_url": "https://github.com/acme-corp-forks/mobile-backend",
      "run_number": 23,
      "run_id": "56104472157",
      "run_url": "https://github.com/acme-corp/codeql-devin-fixer/actions/runs/46952668732",
      "run_label": "run-23-2025-12-01-083000",
      "timestamp": "2025-12-01T08:30:00+00:00",
      "issues_found": 3,
      "severity_breakdown": {
        "low": 1,
        "medium": 2
      },
      "category_breakdown": {
        "xss": 1,
        "info-disclosure": 2
      },
      "batches_created": 1,
      "sessions": [
        {
          "session_id": "devin-b178e79f6b9046f7a7d6699484db963e",
          "session_url": "https://app.devin.ai/sessions/b178e79f6b9046f7a7d6699484db963e",
          "batch_id": 1,
          "status": "finished",
          "issue_ids": [
            "ISSUE-006-001",
            "ISSUE-006-002",
            "ISSUE-006-003"
          ],
          "pr_url": ""
        }
      ],
      "issue_fingerprints": [
        {
          "id": "ISSUE-006-001",
          "fingerprint": "ceb064fc2aba73e716886dbeb26b4752",
          "rule_id": "js/xss",
          "severity_tier": "low",
          "cwe_family": "xss",
          "file": "src/views/components/UserProfile.jsx",
          "start_line": 415,
          "description": "Potential xss vulnerability in UserProfile.jsx",
          "resolution": "",
          "code_churn": 2
        },
        {
          "id": "ISSUE-006-002",
          "fingerprint": "ec3654f0aac56dcad6d14302af96f871",
          "rule_id": "js/information-exposure",
          "severity_tier": "medium",
          "cwe_family": "info-disclosure",
          "file": "src/middleware/error_handler.py",
          "start_line": 250,
          "description": "Potential info disclosure vulnerability in error_handler.py",
          "resolution": "",
          "code_churn": 2
        },
        {
          "id": "ISSUE-006-003",
          "fingerprint": "788732c90870379d74be94bb44bfb348",
          "rule_id": "java/information-exposure",
          "severity_tier": "medium",
          "cwe_family": "info-disclosure",
          "file": "src/handlers/ExceptionMapper.java",
          "start_line": 264,
          "description": "Potential info disclosure vulnerability in ExceptionMapper.java",
          "resolution": "",
          "code_churn": 3
        }
      ]
    },
    {
      "target_repo": "https://github.com/acme-corp/mobile-backend",
      "fork_url": "https://github.com/acme-corp-forks/mobile-backend",
      "run_number": 24,
      "run_id": "59263319540",
      "run_url": "https://github.com/acme-corp/codeql-devin-fixer/actions/runs/54703514686",
      "run_label": "run-24-2025-12-03-182300",
      "timestamp": "2025-12-03T18:23:00+00:00",
      "issues_found": 2,
      "severity_breakdown": {
        "medium": 2
      },
      "category_breakdown": {
        "injection": 1,
        "insecure-deserialization": 1
      },
      "batches_created": 1,
      "sessions": [
        {
          "session_id": "devin-ddbbac8b2dae406d880f3642c9f865c3",
          "session_url": "https://app.devin.ai/sessions/ddbbac8b2dae406d880f3642c9f865c3",
          "batch_id": 1,
          "status": "finished",
          "issue_ids": [
            "ISSUE-007-001",
            "ISSUE-007-002"
          ],
          "pr_url": ""
        }
      ],
      "issue_fingerprints": [
        {
          "id": "ISSUE-007-001",
          "fingerprint": "e11e41e06f1a2f4d0534a012dfd5b6f2",
          "rule_id": "java/sql-injection",
          "severity_tier": "medium",
          "cwe_family": "injection",
          "file": "src/api/controllers/users.py",
          "start_line": 400,
          "description": "Potential injection vulnerability in users.py",
          "resolution": "",
          "code_churn": 1
        },
        {
          "id": "ISSUE-007-002",
          "fingerprint": "ac9d55c8a59ea732254866a728e1fa8c",
          "rule_id": "java/unsafe-deserialization",
          "severity_tier": "medium",
          "cwe_family": "insecure-deserialization",
          "file": "src/api/import_handler.py",
          "start_line": 310,
          "description": "Potential insecure deserialization vulnerability in import_handler.py",
          "resolution": "",
          "code_churn": 3
        }
      ]
    },
    {
      "target_repo": "https://github.com/acme-corp/mobile-backend",
      "fork_url": "https://github.com/acme-corp-forks/mobile-backend",
      "run_number": 25,
      "run_id": "86748348939",
      "run_url": "https://github.com/acme-corp/codeql-devin-fixer/actions/runs/67818748157",
      "run_label": "run-25-2026-01-23-064800",
      "timestamp": "2026-01-23T06:48:00+00:00",
      "issues_found": 2,
      "severity_breakdown": {
        "medium": 2
      },
      "category_breakdown": {
        "insecure-deserialization": 1,
        "auth-bypass": 1
      },
      "batches_created": 1,
      "sessions": [
        {
          "session_id": "devin-d4d84debc820498faa0c4f6cae19eb0a",
          "session_url": "https://app.devin.ai/sessions/d4d84debc820498faa0c4f6cae19eb0a",
          "batch_id": 1,
          "status": "finished",
          "issue_ids": [
            "ISSUE-008-001",
            "ISSUE-008-002"
          ],
          "pr_url": "https://github.com/acme-corp-forks/mobile-backend/pull/14"
        }
      ],
      "issue_fingerprints": [
        {
          "id": "ISSUE-008-001",
          "fingerprint": "a23900fe8b8ff0cba51827ca7e3a189a",
          "rule_id": "java/unsafe-deserialization",
          "severity_tier": "medium",
          "cwe_family": "insecure-deserialization",
          "file": "src/services/DataImporter.java",
          "start_line": 426,
          "description": "Potential insecure deserialization vulnerability in DataImporter.java",
          "resolution": "",
          "code_churn": 0
        },
        {
          "id": "ISSUE-008-002",
          "fingerprint": "cf7a4b038fcf109bc31cc9cce32659ad",
          "rule_id": "js/missing-auth-check",
          "severity_tier": "medium",
          "cwe_family": "auth-bypass",
          "file": "src/api/middleware/auth.js",
          "start_line": 70,
          "description": "Potential auth bypass vulnerability in auth.js",
          "resolution": "",
          "code_churn": 3
        }
      ]
    },
    {
      "target_repo": "https://github.com/acme-corp/mobile-backend",
      "fork_url": "https://github.com/acme-corp-forks/mobile-backend",
      "run_number": 26,
      "run_id": "10521521078",
      "run_url": "https://github.com/acme-corp/codeql-devin-fixer/actions/runs/49334934709",
      "run_label": "run-26-2026-01-23-074900",
      "timestamp": "2026-01-23T07:49:00+00:00",
      "issues_found": 1,
      "severity_breakdown": {
        "low": 1
      },
      "category_breakdown": {
        "insecure-deserialization": 1
      },
      "batches_created": 1,
      "sessions": [
        {
          "session_id": "devin-65434266c39049d7bf73962b20b73a6a",
          "session_url": "https://app.devin.ai/sessions/65434266c39049d7bf73962b20b73a6a",
          "batch_id": 1,
          "status": "finished",
          "issue_ids": [
            "ISSUE-009-001"
          ],
          "pr_url": "https://github.com/acme-corp-forks/mobile-backend/pull/15"
        }
      ],
      "issue_fingerprints": [
        {
          "id": "ISSUE-009-001",
          "fingerprint": "3d9a2fbb27f70455ab597950ccc9203a",
          "rule_id": "py/unsafe-deserialization",
          "severity_tier": "low",
          "cwe_family": "insecure-deserialization",
          "file": "src/api/import_handler.py",
          "start_line": 146,
          "description": "Potential insecure deserialization vulnerability in import_handler.py",
          "resolution": "",
          "code_churn": 1
        }
      ]
    },
    {
      "target_repo": "https://github.com/acme-corp/mobile-backend",
      "fork_url": "https://github.com/acme-corp-forks/mobile-backend",
      "run_number": 27,
      "run_id": "71176358403",
      "run_url": "https://github.com/acme-corp/codeql-devin-fixer/actions/runs/29547534656",
      "run_label": "run-27-2026-01-25-073600",
      "timestamp": "2026-01-25T07:36:00+00:00",
      "issues_found": 2,
      "severity_breakdown": {
        "high": 1,
        "medium": 1
      },
      "category_breakdown": {
        "xss": 1,
        "info-disclosure": 1
      },
      "batches_created": 1,
      "sessions": [
        {
          "session_id": "devin-5973e9c2b1954cf5ab8caefb50109de5",
          "session_url": "https://app.devin.ai/sessions/5973e9c2b1954cf5ab8caefb50109de5",
          "batch_id": 1,
          "status": "error",
          "issue_ids": [
            "ISSUE-010-001",
            "ISSUE-010-002"
          ],
          "pr_url": ""
        }
      ],
      "issue_fingerprints": [
        {
          "id": "ISSUE-010-001",
          "fingerprint": "15d5f256ab29e327198fff32ea0d3c93",
          "rule_id": "js/reflected-xss",
          "severity_tier": "high",
          "cwe_family": "xss",
          "file": "src/views/components/UserProfile.jsx",
          "start_line": 341,
          "description": "Potential xss vulnerability in UserProfile.jsx",
          "resolution": "",
          "code_churn": 1
        },
        {
          "id": "ISSUE-010-002",
          "fingerprint": "f12f739fd437fcdfc8cc4192cdf6463d",
          "rule_id": "java/information-exposure",
          "severity_tier": "medium",
          "cwe_family": "info-disclosure",
          "file": "src/handlers/ExceptionMapper.java",
          "start_line": 150,
          "description": "Potential info disclosure vulnerability in ExceptionMapper.java",
          "resolution": "",
          "code_churn": 3
        }
      ]
    },
    {
      "target_repo": "https://github.com/acme-corp/data-pipeline",
      "fork_url": "https://github.com/acme-corp-forks/data-pipeline",
      "run_number": 28,
      "run_id": "93247393883",
      "run_url": "https://github.com/acme-corp/codeql-devin-fixer/actions/runs/42998811755",
      "run_label": "run-28-2025-11-01-104600",
      "timestamp": "2025-11-01T10:46:00+00:00",
      "issues_found": 12,
      "severity_breakdown": {
        "high": 6,
        "medium": 2,
        "critical": 2,
        "low": 2
      },
      "category_breakdown": {
        "insecure-deserialization": 1,
        "auth-bypass": 4,
        "ssrf": 2,
        "path-traversal": 1,
        "info-disclosure": 2,
        "injection": 1,
        "xss": 1
      },
      "batches_created": 2,
      "sessions": [
        {
          "session_id": "devin-eeb6ad185681444c8c1cd3e7ea6ad337",
          "session_url": "https://app.devin.ai/sessions/eeb6ad185681444c8c1cd3e7ea6ad337",
          "batch_id": 1,
          "status": "stopped",
          "issue_ids": [
            "ISSUE-001-001",
            "ISSUE-001-002",
            "ISSUE-001-003",
            "ISSUE-001-004",
            "ISSUE-001-005",
            "ISSUE-001-006"
          ],
          "pr_url": ""
        },
        {
          "session_id": "devin-e899a2f0dbf94ae882042fb3d0c46cad",
          "session_url": "https://app.devin.ai/sessions/e899a2f0dbf94ae882042fb3d0c46cad",
          "batch_id": 2,
          "status": "finished",
          "issue_ids": [
            "ISSUE-001-007",
            "ISSUE-001-008",
            "ISSUE-001-009",
            "ISSUE-001-010",
            "ISSUE-001-011",
            "ISSUE-001-012"
          ],
          "pr_url": "https://github.com/acme-corp-forks/data-pipeline/pull/16"
        }
      ],
      "issue_fingerprints": [
        {
          "id": "ISSUE-001-001",
          "fingerprint": "f8f37866eb775db6d416de3bbcec8afd",
          "rule_id": "java/unsafe-deserialization",
          "severity_tier": "high",
          "cwe_family": "insecure-deserialization",
          "file": "src/services/DataImporter.java",
          "start_line": 292,
          "description": "Potential insecure deserialization vulnerability in DataImporter.java",
          "resolution": "",
          "code_churn": 3
        },
        {
          "id": "ISSUE-001-002",
          "fingerprint": "10de19318e691080f1197bf345ca571d",
          "rule_id": "py/insecure-auth",
          "severity_tier": "high",
          "cwe_family": "auth-bypass",
          "file": "src/middleware/auth.py",
          "start_line": 303,
          "description": "Potential auth bypass vulnerability in auth.py",
          "resolution": "",
          "code_churn": 3
        },
        {
          "id": "ISSUE-001-003",
          "fingerprint": "69035da9e2c86ad5ec681c65ce554dac",
          "rule_id": "py/ssrf",
          "severity_tier": "high",
          "cwe_family": "ssrf",
          "file": "src/services/WebhookClient.java",
          "start_line": 393,
          "description": "Potential ssrf vulnerability in WebhookClient.java",
          "resolution": "",
          "code_churn": 3
        },
        {
          "id": "ISSUE-001-004",
          "fingerprint": "d8ad0be8f97c78b2f42d865a9c3321d1",
          "rule_id": "java/ssrf",
          "severity_tier": "medium",
          "cwe_family": "ssrf",
          "file": "src/services/webhook_sender.py",
          "start_line": 266,
          "description": "Potential ssrf vulnerability in webhook_sender.py",
          "resolution": "",
          "code_churn": 0
        },
        {
          "id": "ISSUE-001-005",
          "fingerprint": "b3aea284c6744cc934f9670b3379962b",
          "rule_id": "py/insecure-auth",
          "severity_tier": "critical",
          "cwe_family": "auth-bypass",
          "file": "src/api/middleware/auth.js",
          "start_line": 65,
          "description": "Potential auth bypass vulnerability in auth.js",
          "resolution": "",
          "code_churn": 3
        },
        {
          "id": "ISSUE-001-006",
          "fingerprint": "58589c00d3515e05fa2f37bfca822f85",
          "rule_id": "py/path-injection",
          "severity_tier": "critical",
          "cwe_family": "path-traversal",
          "file": "src/services/FileService.java",
          "start_line": 94,
          "description": "Potential path traversal vulnerability in FileService.java",
          "resolution": "",
          "code_churn": 0
        },
        {
          "id": "ISSUE-001-007",
          "fingerprint": "88702912e54abe4a0e317607e0002082",
          "rule_id": "js/information-exposure",
          "severity_tier": "high",
          "cwe_family": "info-disclosure",
          "file": "src/handlers/ExceptionMapper.java",
          "start_line": 370,
          "description": "Potential info disclosure vulnerability in ExceptionMapper.java",
          "resolution": "",
          "code_churn": 3
        },
        {
          "id": "ISSUE-001-008",
          "fingerprint": "ef6352ed6deea6dbd50bcbeb089faf42",
          "rule_id": "js/missing-auth-check",
          "severity_tier": "medium",
          "cwe_family": "auth-bypass",
          "file": "src/api/middleware/auth.js",
          "start_line": 337,
          "description": "Potential auth bypass vulnerability in auth.js",
          "resolution": "",
          "code_churn": 3
        },
        {
          "id": "ISSUE-001-009",
          "fingerprint": "b998529420fd52be1229d38f65a6a168",
          "rule_id": "js/sql-injection",
          "severity_tier": "low",
          "cwe_family": "injection",
          "file": "src/api/controllers/search.js",
          "start_line": 341,
          "description": "Potential injection vulnerability in search.js",
          "resolution": "",
          "code_churn": 2
        },
        {
          "id": "ISSUE-001-010",
          "fingerprint": "950cb082d41bd9c92831a073a3a706ff",
          "rule_id": "js/reflected-xss",
          "severity_tier": "low",
          "cwe_family": "xss",
          "file": "src/views/components/UserProfile.jsx",
          "start_line": 408,
          "description": "Potential xss vulnerability in UserProfile.jsx",
          "resolution": "",
          "code_churn": 0
        },
        {
          "id": "ISSUE-001-011",
          "fingerprint": "9e1744f212c381aaa221946e01b61fe1",
          "rule_id": "py/stack-trace-exposure",
          "severity_tier": "high",
          "cwe_family": "info-disclosure",
          "file": "src/middleware/error_handler.py",
          "start_line": 186,
          "description": "Potential info disclosure vulnerability in error_handler.py",
          "resolution": "",
          "code_churn": 0
        },
        {
          "id": "ISSUE-001-012",
          "fingerprint": "6b51b7a553c2da6ab26530c986744b64",
          "rule_id": "js/missing-auth-check",
          "severity_tier": "high",
          "cwe_family": "auth-bypass",
          "file": "src/middleware/auth.py",
          "start_line": 146,
          "description": "Potential auth bypass vulnerability in auth.py",
          "resolution": "",
          "code_churn": 3
        }
      ]
    },
    {
      "target_repo": "https://github.com/acme-corp/data-pipeline",
      "fork_url": "https://github.com/acme-corp-forks/data-pipeline",
      "run_number": 29,
      "run_id": "18476559573",
      "run_url": "https://github.com/acme-corp/codeql-devin-fixer/actions/runs/95515448654",
      "run_label": "run-29-2025-11-18-071700",
      "timestamp": "2025-11-18T07:17:00+00:00",
      "issues_found": 3,
      "severity_breakdown": {
        "medium": 2,
        "high": 1
      },
      "category_breakdown": {
        "ssrf": 2,
        "info-disclosure": 1
      },
      "batches_created": 1,
      "sessions": [
        {
          "session_id": "devin-e535bbf37fd041ab8f37f662724104eb",
          "session_url": "https://app.devin.ai/sessions/e535bbf37fd041ab8f37f662724104eb",
          "batch_id": 1,
          "status": "finished",
          "issue_ids": [
            "ISSUE-002-001",
            "ISSUE-002-002",
            "ISSUE-002-003"
          ],
          "pr_url": ""
        }
      ],
      "issue_fingerprints": [
        {
          "id": "ISSUE-002-001",
          "fingerprint": "f215aafba3f2295345865a356a14f728",
          "rule_id": "java/ssrf",
          "severity_tier": "medium",
          "cwe_family": "ssrf",
          "file": "src/services/WebhookClient.java",
          "start_line": 442,
          "description": "Potential ssrf vulnerability in WebhookClient.java",
          "resolution": "",
          "code_churn": 2
        },
        {
          "id": "ISSUE-002-002",
          "fingerprint": "dd198a21163adb511864a889720b56b7",
          "rule_id": "java/ssrf",
          "severity_tier": "high",
          "cwe_family": "ssrf",
          "file": "src/services/webhook_sender.py",
          "start_line": 132,
          "description": "Potential ssrf vulnerability in webhook_sender.py",
          "resolution": "",
          "code_churn": 3
        },
        {
          "id": "ISSUE-002-003",
          "fingerprint": "b1a45a19de5d561af0bb75efc0b7f955",
          "rule_id": "java/information-exposure",
          "severity_tier": "medium",
          "cwe_family": "info-disclosure",
          "file": "src/api/error_boundary.js",
          "start_line": 23,
          "description": "Potential info disclosure vulnerability in error_boundary.js",
          "resolution": "",
          "code_churn": 3
        }
      ]
    },
    {
      "target_repo": "https://github.com/acme-corp/data-pipeline",
      "fork_url": "https://github.com/acme-corp-forks/data-pipeline",
      "run_number": 30,
      "run_id": "80999470334",
      "run_url": "https://github.com/acme-corp/codeql-devin-fixer/actions/runs/48283135050",
      "run_label": "run-30-2025-11-25-153200",
      "timestamp": "2025-11-25T15:32:00+00:00",
      "issues_found": 4,
      "severity_breakdown": {
        "high": 2,
        "medium": 1,
        "critical": 1
      },
      "category_breakdown": {
        "auth-bypass": 1,
        "path-traversal": 1,
        "insecure-deserialization": 1,
        "info-disclosure": 1
      },
      "batches_created": 2,
      "sessions": [
        {
          "session_id": "devin-c1137c692d384b2ea21575b8c258915b",
          "session_url": "https://app.devin.ai/sessions/c1137c692d384b2ea21575b8c258915b",
          "batch_id": 1,
          "status": "finished",
          "issue_ids": [
            "ISSUE-003-001",
            "ISSUE-003-002"
          ],
          "pr_url": "https://github.com/acme-corp-forks/data-pipeline/pull/17"
        },
        {
          "session_id": "devin-2a5d7de9b25d44b4b3846566a4403734",
          "session_url": "https://app.devin.ai/sessions/2a5d7de9b25d44b4b3846566a4403734",
          "batch_id": 2,
          "status": "error",
          "issue_ids": [
            "ISSUE-003-003",
            "ISSUE-003-004"
          ],
          "pr_url": ""
        }
      ],
      "issue_fingerprints": [
        {
          "id": "ISSUE-003-001",
          "fingerprint": "46bdb4af2de7d29cc65325173b738a9c",
          "rule_id": "py/insecure-auth",
          "severity_tier": "high",
          "cwe_family": "auth-bypass",
          "file": "src/middleware/auth.py",
          "start_line": 327,
          "description": "Potential auth bypass vulnerability in auth.py",
          "resolution": "",
          "code_churn": 2
        },
        {
          "id": "ISSUE-003-002",
          "fingerprint": "2d8b7acd1fbc18f209a21d0b4fe018a8",
          "rule_id": "java/path-injection",
          "severity_tier": "medium",
          "cwe_family": "path-traversal",
          "file": "src/utils/file_handler.py",
          "start_line": 473,
          "description": "Potential path traversal vulnerability in file_handler.py",
          "resolution": "",
          "code_churn": 0
        },
        {
          "id": "ISSUE-003-003",
          "fingerprint": "a6658650dc44ab7e0d8726aa833d30b3",
          "rule_id": "py/unsafe-deserialization",
          "severity_tier": "high",
          "cwe_family": "insecure-deserialization",
          "file": "src/services/DataImporter.java",
          "start_line": 386,
          "description": "Potential insecure deserialization vulnerability in DataImporter.java",
          "resolution": "",
          "code_churn": 1
        },
        {
          "id": "ISSUE-003-004",
          "fingerprint": "5b977fcbdb32fe051a4ca5ff7f8dda1a",
          "rule_id": "js/information-exposure",
          "severity_tier": "critical",
          "cwe_family": "info-disclosure",
          "file": "src/handlers/ExceptionMapper.java",
          "start_line": 225,
          "description": "Potential info disclosure vulnerability in ExceptionMapper.java",
          "resolution": "",
          "code_churn": 1
        }
      ]
    },
    {
      "target_repo": "https://github.com/acme-corp/data-pipeline",
      "fork_url": "https://github.com/acme-corp-forks/data-pipeline",
      "run_number": 31,
      "run_id": "44419518557",
      "run_url": "https://github.com/acme-corp/codeql-devin-fixer/actions/runs/25189462425",
      "run_label": "run-31-2025-12-09-153700",
      "timestamp": "2025-12-09T15:37:00+00:00",
      "issues_found": 2,
      "severity_breakdown": {
        "low": 2
      },
      "category_breakdown": {
        "auth-bypass": 1,
        "crypto": 1
      },
      "batches_created": 1,
      "sessions": [
        {
          "session_id": "devin-94725e93cba240db912d8f9ca1bed863",
          "session_url": "https://app.devin.ai/sessions/94725e93cba240db912d8f9ca1bed863",
          "batch_id": 1,
          "status": "finished",
          "issue_ids": [
            "ISSUE-004-001",
            "ISSUE-004-002"
          ],
          "pr_url": ""
        }
      ],
      "issue_fingerprints": [
        {
          "id": "ISSUE-004-001",
          "fingerprint": "c58b7eb5b5471575ab12b9fb25cd19a6",
          "rule_id": "py/insecure-auth",
          "severity_tier": "low",
          "cwe_family": "auth-bypass",
          "file": "src/api/middleware/auth.js",
          "start_line": 48,
          "description": "Potential auth bypass vulnerability in auth.js",
          "resolution": "",
          "code_churn": 1
        },
        {
          "id": "ISSUE-004-002",
          "fingerprint": "25ed4a726a00f727a09d24e01a932a63",
          "rule_id": "java/weak-crypto",
          "severity_tier": "low",
          "cwe_family": "crypto",
          "file": "src/security/CryptoHelper.java",
          "start_line": 356,
          "description": "Potential crypto vulnerability in CryptoHelper.java",
          "resolution": "",
          "code_churn": 3
        }
      ]
    },
    {
      "target_repo": "https://github.com/acme-corp/data-pipeline",
      "fork_url": "https://github.com/acme-corp-forks/data-pipeline",
      "run_number": 32,
      "run_id": "14895305008",
      "run_url": "https://github.com/acme-corp/codeql-devin-fixer/actions/runs/18359129661",
      "run_label": "run-32-2025-12-24-115900",
      "timestamp": "2025-12-24T11:59:00+00:00",
      "issues_found": 2,
      "severity_breakdown": {
        "high": 1,
        "medium": 1
      },
      "category_breakdown": {
        "ssrf": 1,
        "auth-bypass": 1
      },
      "batches_created": 1,
      "sessions": [
        {
          "session_id": "devin-48337ca2d1e44f1db3f04d6898d7ebd7",
          "session_url": "https://app.devin.ai/sessions/48337ca2d1e44f1db3f04d6898d7ebd7",
          "batch_id": 1,
          "status": "finished",
          "issue_ids": [
            "ISSUE-005-001",
            "ISSUE-005-002"
          ],
          "pr_url": "https://github.com/acme-corp-forks/data-pipeline/pull/18"
        }
      ],
      "issue_fingerprints": [
        {
          "id": "ISSUE-005-001",
          "fingerprint": "4560e1d43259c54e1886f2269e350279",
          "rule_id": "java/ssrf",
          "severity_tier": "high",
          "cwe_family": "ssrf",
          "file": "src/services/webhook_sender.py",
          "start_line": 355,
          "description": "Potential ssrf vulnerability in webhook_sender.py",
          "resolution": "",
          "code_churn": 1
        },
        {
          "id": "ISSUE-005-002",
          "fingerprint": "6a3d78efb79a8d7d699bde24b67578a6",
          "rule_id": "py/insecure-auth",
          "severity_tier": "medium",
          "cwe_family": "auth-bypass",
          "file": "src/middleware/auth.py",
          "start_line": 336,
          "description": "Potential auth bypass vulnerability in auth.py",
          "resolution": "",
          "code_churn": 3
        }
      ]
    },
    {
      "target_repo": "https://github.com/acme-corp/data-pipeline",
      "fork_url": "https://github.com/acme-corp-forks/data-pipeline",
      "run_number": 33,
      "run_id": "97681261401",
      "run_url": "https://github.com/acme-corp/codeql-devin-fixer/actions/runs/93706108143",
      "run_label": "run-33-2026-01-04-105200",
      "timestamp": "2026-01-04T10:52:00+00:00",
      "issues_found": 1,
      "severity_breakdown": {
        "high": 1
      },
      "category_breakdown": {
        "path-traversal": 1
      },
      "batches_created": 1,
      "sessions": [
        {
          "session_id": "devin-f0d64f8ba2764bc8b3c76fc52dcbf2b5",
          "session_url": "https://app.devin.ai/sessions/f0d64f8ba2764bc8b3c76fc52dcbf2b5",
          "batch_id": 1,
          "status": "finished",
          "issue_ids": [
            "ISSUE-006-001"
          ],
          "pr_url": "https://github.com/acme-corp-forks/data-pipeline/pull/19"
        }
      ],
      "issue_fingerprints": [
        {
          "id": "ISSUE-006-001",
          "fingerprint": "8aeb602d35f4f781260b5e12f227a56d",
          "rule_id": "py/path-injection",
          "severity_tier": "high",
          "cwe_family": "path-traversal",
          "file": "src/api/upload.js",
          "start_line": 199,
          "description": "Potential path traversal vulnerability in upload.js",
          "resolution": "",
          "code_churn": 3
        }
      ]
    },
    {
      "target_repo": "https://github.com/acme-corp/data-pipeline",
      "fork_url": "https://github.com/acme-corp-forks/data-pipeline",
      "run_number": 34,
      "run_id": "20542930840",
      "run_url": "https://github.com/acme-corp/codeql-devin-fixer/actions/runs/38616373834",
      "run_label": "run-34-2026-01-24-135500",
      "timestamp": "2026-01-24T13:55:00+00:00",
      "issues_found": 2,
      "severity_breakdown": {
        "medium": 1,
        "low": 1
      },
      "category_breakdown": {
        "auth-bypass": 1,
        "xss": 1
      },
      "batches_created": 1,
      "sessions": [
        {
          "session_id": "devin-6269a76472584e189eea8ff4ae53bd16",
          "session_url": "https://app.devin.ai/sessions/6269a76472584e189eea8ff4ae53bd16",
          "batch_id": 1,
          "status": "finished",
          "issue_ids": [
            "ISSUE-007-001",
            "ISSUE-007-002"
          ],
          "pr_url": "https://github.com/acme-corp-forks/data-pipeline/pull/20"
        }
      ],
      "issue_fingerprints": [
        {
          "id": "ISSUE-007-001",
          "fingerprint": "ef47bf66451062b601ab093bb5ea1c51",
          "rule_id": "py/insecure-auth",
          "severity_tier": "medium",
          "cwe_family": "auth-bypass",
          "file": "src/api/middleware/auth.js",
          "start_line": 237,
          "description": "Potential auth bypass vulnerability in auth.js",
          "resolution": "",
          "code_churn": 1
        },
        {
          "id": "ISSUE-007-002",
          "fingerprint": "336971ccc67ad6654578ce11bd0aef0b",
          "rule_id": "js/stored-xss",
          "severity_tier": "low",
          "cwe_family": "xss",
          "file": "src/templates/comment.html",
          "start_line": 289,
          "description": "Potential xss vulnerability in comment.html",
          "resolution": "",
          "code_churn": 2
        }
      ]
    },
    {
      "target_repo": "https://github.com/acme-corp/internal-tools",
      "fork_url": "https://github.com/acme-corp-forks/internal-tools",
      "run_number": 35,
      "run_id": "18956571740",
      "run_url": "https://github.com/acme-corp/codeql-devin-fixer/actions/runs/24739797409",
      "run_label": "run-35-2025-11-07-182100",
      "timestamp": "2025-11-07T18:21:00+00:00",
      "issues_found": 13,
      "severity_breakdown": {
        "low": 2,
        "high": 3,
        "critical": 4,
        "medium": 4
      },
      "category_breakdown": {
        "crypto": 2,
        "path-traversal": 1,
        "injection": 2,
        "xss": 5,
        "info-disclosure": 1,
        "ssrf": 1,
        "auth-bypass": 1
      },
      "batches_created": 3,
      "sessions": [
        {
          "session_id": "devin-ddeed815337f423b8b474f90ed35873d",
          "session_url": "https://app.devin.ai/sessions/ddeed815337f423b8b474f90ed35873d",
          "batch_id": 1,
          "status": "error",
          "issue_ids": [
            "ISSUE-001-001",
            "ISSUE-001-002",
            "ISSUE-001-003",
            "ISSUE-001-004"
          ],
          "pr_url": ""
        },
        {
          "session_id": "devin-afd8f02506ba45f7a491e5dae92ba840",
          "session_url": "https://app.devin.ai/sessions/afd8f02506ba45f7a491e5dae92ba840",
          "batch_id": 2,
          "status": "stopped",
          "issue_ids": [
            "ISSUE-001-005",
            "ISSUE-001-006",
            "ISSUE-001-007",
            "ISSUE-001-008"
          ],
          "pr_url": ""
        },
        {
          "session_id": "devin-535bd9e306b34531af61863108a27f1c",
          "session_url": "https://app.devin.ai/sessions/535bd9e306b34531af61863108a27f1c",
          "batch_id": 3,
          "status": "finished",
          "issue_ids": [
            "ISSUE-001-009",
            "ISSUE-001-010",
            "ISSUE-001-011",
            "ISSUE-001-012"
          ],
          "pr_url": "https://github.com/acme-corp-forks/internal-tools/pull/21"
        }
      ],
      "issue_fingerprints": [
        {
          "id": "ISSUE-001-001",
          "fingerprint": "3a5b07fc7e917ced3bf013bc2fb44811",
          "rule_id": "js/weak-crypto",
          "severity_tier": "low",
          "cwe_family": "crypto",
          "file": "src/auth/token_manager.py",
          "start_line": 413,
          "description": "Potential crypto vulnerability in token_manager.py",
          "resolution": "",
          "code_churn": 0
        },
        {
          "id": "ISSUE-001-002",
          "fingerprint": "47d3ea4e5d59567a42f17f15d96ae07f",
          "rule_id": "js/path-injection",
          "severity_tier": "high",
          "cwe_family": "path-traversal",
          "file": "src/services/FileService.java",
          "start_line": 139,
          "description": "Potential path traversal vulnerability in FileService.java",
          "resolution": "",
          "code_churn": 1
        },
        {
          "id": "ISSUE-001-003",
          "fingerprint": "42d974ab08ed582240f064c9a6b3ff82",
          "rule_id": "py/sql-injection",
          "severity_tier": "critical",
          "cwe_family": "injection",
          "file": "src/api/controllers/users.py",
          "start_line": 195,
          "description": "Potential injection vulnerability in users.py",
          "resolution": "",
          "code_churn": 1
        },
        {
          "id": "ISSUE-001-004",
          "fingerprint": "dc335dd1fb4f0c8387c8aa5e6ee6ab6e",
          "rule_id": "py/sql-injection",
          "severity_tier": "medium",
          "cwe_family": "injection",
          "file": "src/services/QueryBuilder.java",
          "start_line": 39,
          "description": "Potential injection vulnerability in QueryBuilder.java",
          "resolution": "",
          "code_churn": 1
        },
        {
          "id": "ISSUE-001-005",
          "fingerprint": "64163f38daefa2330a711864374a2f65",
          "rule_id": "js/stored-xss",
          "severity_tier": "medium",
          "cwe_family": "xss",
          "file": "src/views/components/UserProfile.jsx",
          "start_line": 257,
          "description": "Potential xss vulnerability in UserProfile.jsx",
          "resolution": "",
          "code_churn": 3
        },
        {
          "id": "ISSUE-001-006",
          "fingerprint": "efea3a2c44521ec0c0bf70c86a3fa05b",
          "rule_id": "js/reflected-xss",
          "severity_tier": "medium",
          "cwe_family": "xss",
          "file": "src/views/dashboard.js",
          "start_line": 128,
          "description": "Potential xss vulnerability in dashboard.js",
          "resolution": "",
          "code_churn": 0
        },
        {
          "id": "ISSUE-001-007",
          "fingerprint": "7784dd14d90a677989be04f2622d97fd",
          "rule_id": "js/information-exposure",
          "severity_tier": "medium",
          "cwe_family": "info-disclosure",
          "file": "src/handlers/ExceptionMapper.java",
          "start_line": 31,
          "description": "Potential info disclosure vulnerability in ExceptionMapper.java",
          "resolution": "",
          "code_churn": 0
        },
        {
          "id": "ISSUE-001-008",
          "fingerprint": "7ce75818cf41904f3673ea81ab60de73",
          "rule_id": "java/ssrf",
          "severity_tier": "low",
          "cwe_family": "ssrf",
          "file": "src/services/webhook_sender.py",
          "start_line": 268,
          "description": "Potential ssrf vulnerability in webhook_sender.py",
          "resolution": "",
          "code_churn": 3
        },
        {
          "id": "ISSUE-001-009",
          "fingerprint": "b876e47a2e3b1d4b6875720b841ac4bc",
          "rule_id": "js/reflected-xss",
          "severity_tier": "critical",
          "cwe_family": "xss",
          "file": "src/views/dashboard.js",
          "start_line": 93,
          "description": "Potential xss vulnerability in dashboard.js",
          "resolution": "",
          "code_churn": 0
        },
        {
          "id": "ISSUE-001-010",
          "fingerprint": "e73dc3d05a8d055b84738c3c9fc974c1",
          "rule_id": "js/missing-auth-check",
          "severity_tier": "critical",
          "cwe_family": "auth-bypass",
          "file": "src/api/middleware/auth.js",
          "start_line": 251,
          "description": "Potential auth bypass vulnerability in auth.js",
          "resolution": "",
          "code_churn": 3
        },
        {
          "id": "ISSUE-001-011",
          "fingerprint": "75e52fd8d3ac3dd324b99b740c5b9ddc",
          "rule_id": "js/stored-xss",
          "severity_tier": "critical",
          "cwe_family": "xss",
          "file": "src/views/dashboard.js",
          "start_line": 469,
          "description": "Potential xss vulnerability in dashboard.js",
          "resolution": "",
          "code_churn": 1
        },
        {
          "id": "ISSUE-001-012",
          "fingerprint": "afd5eb6721c7dea72561e26b24512f9e",
          "rule_id": "js/weak-crypto",
          "severity_tier": "high",
          "cwe_family": "crypto",
          "file": "src/utils/encryption.js",
          "start_line": 444,
          "description": "Potential crypto vulnerability in encryption.js",
          "resolution": "",
          "code_churn": 3
        },
        {
          "id": "ISSUE-001-013",
          "fingerprint": "fae1d9804b307c3c5efb85d1e9f0cdfe",
          "rule_id": "js/reflected-xss",
          "severity_tier": "high",
          "cwe_family": "xss",
          "file": "src/templates/comment.html",
          "start_line": 182,
          "description": "Potential xss vulnerability in comment.html",
          "resolution": "",
          "code_churn": 2
        }
      ]
    },
    {
      "target_repo": "https://github.com/acme-corp/internal-tools",
      "fork_url": "https://github.com/acme-corp-forks/internal-tools",
      "run_number": 36,
      "run_id": "76245639018",
      "run_url": "https://github.com/acme-corp/codeql-devin-fixer/actions/runs/72736913741",
      "run_label": "run-36-2025-12-02-085000",
      "timestamp": "2025-12-02T08:50:00+00:00",
      "issues_found": 7,
      "severity_breakdown": {
        "high": 3,
        "low": 2,
        "medium": 1,
        "critical": 1
      },
      "category_breakdown": {
        "crypto": 2,
        "auth-bypass": 1,
        "ssrf": 2,
        "info-disclosure": 2
      },
      "batches_created": 2,
      "sessions": [
        {
          "session_id": "devin-99baaaf538eb415aa867279ef2e8d6ff",
          "session_url": "https://app.devin.ai/sessions/99baaaf538eb415aa867279ef2e8d6ff",
          "batch_id": 1,
          "status": "finished",
          "issue_ids": [
            "ISSUE-002-001",
            "ISSUE-002-002",
            "ISSUE-002-003"
          ],
          "pr_url": ""
        },
        {
          "session_id": "devin-1acf0fa3b8264dab8dcb8e4aba52325b",
          "session_url": "https://app.devin.ai/sessions/1acf0fa3b8264dab8dcb8e4aba52325b",
          "batch_id": 2,
          "status": "finished",
          "issue_ids": [
            "ISSUE-002-004",
            "ISSUE-002-005",
            "ISSUE-002-006"
          ],
          "pr_url": "https://github.com/acme-corp-forks/internal-tools/pull/22"
        }
      ],
      "issue_fingerprints": [
        {
          "id": "ISSUE-002-001",
          "fingerprint": "498880d1dd3f90f05b8c1cd8deb0ed69",
          "rule_id": "py/weak-crypto",
          "severity_tier": "high",
          "cwe_family": "crypto",
          "file": "src/security/CryptoHelper.java",
          "start_line": 256,
          "description": "Potential crypto vulnerability in CryptoHelper.java",
          "resolution": "",
          "code_churn": 1
        },
        {
          "id": "ISSUE-002-002",
          "fingerprint": "0ccaf04b848017056c2972b125a8a4f0",
          "rule_id": "js/missing-auth-check",
          "severity_tier": "low",
          "cwe_family": "auth-bypass",
          "file": "src/middleware/auth.py",
          "start_line": 401,
          "description": "Potential auth bypass vulnerability in auth.py",
          "resolution": "",
          "code_churn": 2
        },
        {
          "id": "ISSUE-002-003",
          "fingerprint": "8f2d27b53792f78f0d308c02f7409551",
          "rule_id": "py/ssrf",
          "severity_tier": "medium",
          "cwe_family": "ssrf",
          "file": "src/services/WebhookClient.java",
          "start_line": 26,
          "description": "Potential ssrf vulnerability in WebhookClient.java",
          "resolution": "",
          "code_churn": 1
        },
        {
          "id": "ISSUE-002-004",
          "fingerprint": "4690e98d45c2b8dde651012159cb8a2b",
          "rule_id": "js/information-exposure",
          "severity_tier": "high",
          "cwe_family": "info-disclosure",
          "file": "src/api/error_boundary.js",
          "start_line": 16,
          "description": "Potential info disclosure vulnerability in error_boundary.js",
          "resolution": "",
          "code_churn": 1
        },
        {
          "id": "ISSUE-002-005",
          "fingerprint": "e6364fa8c6ced1c69cc5c7d8fbb5a518",
          "rule_id": "py/ssrf",
          "severity_tier": "low",
          "cwe_family": "ssrf",
          "file": "src/services/webhook_sender.py",
          "start_line": 393,
          "description": "Potential ssrf vulnerability in webhook_sender.py",
          "resolution": "",
          "code_churn": 0
        },
        {
          "id": "ISSUE-002-006",
          "fingerprint": "33516041c63dd87d99cc8809645ea982",
          "rule_id": "js/weak-crypto",
          "severity_tier": "critical",
          "cwe_family": "crypto",
          "file": "src/utils/encryption.js",
          "start_line": 247,
          "description": "Potential crypto vulnerability in encryption.js",
          "resolution": "",
          "code_churn": 2
        },
        {
          "id": "ISSUE-002-007",
          "fingerprint": "4914a6d6d56a6d2c78a0ddead2497156",
          "rule_id": "java/information-exposure",
          "severity_tier": "high",
          "cwe_family": "info-disclosure",
          "file": "src/api/error_boundary.js",
          "start_line": 413,
          "description": "Potential info disclosure vulnerability in error_boundary.js",
          "resolution": "",
          "code_churn": 0
        }
      ]
    },
    {
      "target_repo": "https://github.com/acme-corp/internal-tools",
      "fork_url": "https://github.com/acme-corp-forks/internal-tools",
      "run_number": 37,
      "run_id": "79707794726",
      "run_url": "https://github.com/acme-corp/codeql-devin-fixer/actions/runs/20111071023",
      "run_label": "run-37-2026-01-10-093700",
      "timestamp": "2026-01-10T09:37:00+00:00",
      "issues_found": 3,
      "severity_breakdown": {
        "medium": 1,
        "critical": 1,
        "high": 1
      },
      "category_breakdown": {
        "injection": 1,
        "info-disclosure": 1,
        "xss": 1
      },
      "batches_created": 1,
      "sessions": [
        {
          "session_id": "devin-c8c1891ba21841dcb67297e495ec4869",
          "session_url": "https://app.devin.ai/sessions/c8c1891ba21841dcb67297e495ec4869",
          "batch_id": 1,
          "status": "finished",
          "issue_ids": [
            "ISSUE-003-001",
            "ISSUE-003-002",
            "ISSUE-003-003"
          ],
          "pr_url": "https://github.com/acme-corp-forks/internal-tools/pull/23"
        }
      ],
      "issue_fingerprints": [
        {
          "id": "ISSUE-003-001",
          "fingerprint": "55561ef1f325fc4da0ff191c31ff283f",
          "rule_id": "py/sql-injection",
          "severity_tier": "medium",
          "cwe_family": "injection",
          "file": "src/db/queries.py",
          "start_line": 316,
          "description": "Potential injection vulnerability in queries.py",
          "resolution": "",
          "code_churn": 0
        },
        {
          "id": "ISSUE-003-002",
          "fingerprint": "aaf08d9d58e3f0cb464aed3aeddfd7fd",
          "rule_id": "py/stack-trace-exposure",
          "severity_tier": "critical",
          "cwe_family": "info-disclosure",
          "file": "src/middleware/error_handler.py",
          "start_line": 402,
          "description": "Potential info disclosure vulnerability in error_handler.py",
          "resolution": "",
          "code_churn": 2
        },
        {
          "id": "ISSUE-003-003",
          "fingerprint": "1da9a8ef99131b6a357a0df1f136cbc3",
          "rule_id": "js/xss",
          "severity_tier": "high",
          "cwe_family": "xss",
          "file": "src/templates/comment.html",
          "start_line": 394,
          "description": "Potential xss vulnerability in comment.html",
          "resolution": "",
          "code_churn": 3
        }
      ]
    },
    {
      "target_repo": "https://github.com/acme-corp/internal-tools",
      "fork_url": "https://github.com/acme-corp-forks/internal-tools",
      "run_number": 38,
      "run_id": "32869705212",
      "run_url": "https://github.com/acme-corp/codeql-devin-fixer/actions/runs/72784369933",
      "run_label": "run-38-2026-01-12-090400",
      "timestamp": "2026-01-12T09:04:00+00:00",
      "issues_found": 1,
      "severity_breakdown": {
        "low": 1
      },
      "category_breakdown": {
        "auth-bypass": 1
      },
      "batches_created": 1,
      "sessions": [
        {
          "session_id": "devin-96f00b606ef548a9a77438db2c1245b4",
          "session_url": "https://app.devin.ai/sessions/96f00b606ef548a9a77438db2c1245b4",
          "batch_id": 1,
          "status": "finished",
          "issue_ids": [
            "ISSUE-004-001"
          ],
          "pr_url": "https://github.com/acme-corp-forks/internal-tools/pull/24"
        }
      ],
      "issue_fingerprints": [
        {
          "id": "ISSUE-004-001",
          "fingerprint": "26c11fba4cea05ac0369ec7885b2eb24",
          "rule_id": "js/missing-auth-check",
          "severity_tier": "low",
          "cwe_family": "auth-bypass",
          "file": "src/api/middleware/auth.js",
          "start_line": 373,
          "description": "Potential auth bypass vulnerability in auth.js",
          "resolution": "",
          "code_churn": 3
        }
      ]
    }
  ],
  "prs": [
    {
      "pr_number": 1,
      "title": "fix: resolve weak crypto vulnerability",
      "html_url": "https://github.com/acme-corp-forks/web-platform/pull/1",
      "state": "open",
      "merged": false,
      "created_at": "2025-11-04T17:39:00+00:00",
      "repo": "https://github.com/acme-corp-forks/web-platform",
      "user": "devin-ai-integration[bot]",
      "session_id": "devin-dd1006b888cd41edaf56adb1ed1acfd3",
      "issue_ids": [
        "ISSUE-001-001",
        "ISSUE-001-002",
        "ISSUE-001-003"
      ]
    },
    {
      "pr_number": 2,
      "title": "fix: resolve XSS vulnerability",
      "html_url": "https://github.com/acme-corp-forks/web-platform/pull/2",
      "state": "closed",
      "merged": true,
      "created_at": "2025-11-12T10:06:00+00:00",
      "repo": "https://github.com/acme-corp-forks/web-platform",
      "user": "devin-ai-integration[bot]",
      "session_id": "devin-d39dcf04246b43c496e3a9a6e3db3182",
      "issue_ids": [
        "ISSUE-002-001"
      ]
    },
    {
      "pr_number": 3,
      "title": "fix: resolve SSRF vulnerability",
      "html_url": "https://github.com/acme-corp-forks/web-platform/pull/3",
      "state": "closed",
      "merged": false,
      "created_at": "2025-12-24T09:38:00+00:00",
      "repo": "https://github.com/acme-corp-forks/web-platform",
      "user": "devin-ai-integration[bot]",
      "session_id": "devin-15b7ef03472246b9aac2e091909c39c5",
      "issue_ids": [
        "ISSUE-005-001"
      ]
    },
    {
      "pr_number": 4,
      "title": "fix: resolve weak crypto vulnerability",
      "html_url": "https://github.com/acme-corp-forks/web-platform/pull/4",
      "state": "closed",
      "merged": true,
      "created_at": "2026-01-11T09:55:00+00:00",
      "repo": "https://github.com/acme-corp-forks/web-platform",
      "user": "devin-ai-integration[bot]",
      "session_id": "devin-9df39e5c3ec545369df27a5af9d282ac",
      "issue_ids": [
        "ISSUE-009-001"
      ]
    },
    {
      "pr_number": 5,
      "title": "fix: resolve SQL injection vulnerability",
      "html_url": "https://github.com/acme-corp-forks/web-platform/pull/5",
      "state": "closed",
      "merged": true,
      "created_at": "2026-01-23T18:17:00+00:00",
      "repo": "https://github.com/acme-corp-forks/web-platform",
      "user": "devin-ai-integration[bot]",
      "session_id": "devin-893593661f6e42d388d9fe473574bf55",
      "issue_ids": [
        "ISSUE-010-001"
      ]
    },
    {
      "pr_number": 6,
      "title": "fix: resolve SSRF vulnerability",
      "html_url": "https://github.com/acme-corp-forks/api-gateway/pull/6",
      "state": "closed",
      "merged": false,
      "created_at": "2025-11-10T15:02:00+00:00",
      "repo": "https://github.com/acme-corp-forks/api-gateway",
      "user": "devin-ai-integration[bot]",
      "session_id": "devin-935ef7725ad24eaa85510b2cf5f13ba4",
      "issue_ids": [
        "ISSUE-001-001",
        "ISSUE-001-002",
        "ISSUE-001-003",
        "ISSUE-001-004"
      ]
    },
    {
      "pr_number": 7,
      "title": "fix: resolve info disclosure vulnerability",
      "html_url": "https://github.com/acme-corp-forks/api-gateway/pull/7",
      "state": "closed",
      "merged": true,
      "created_at": "2025-11-21T14:35:00+00:00",
      "repo": "https://github.com/acme-corp-forks/api-gateway",
      "user": "devin-ai-integration[bot]",
      "session_id": "devin-e16017965e8b4462b182d9cc74877071",
      "issue_ids": [
        "ISSUE-002-001",
        "ISSUE-002-002",
        "ISSUE-002-003"
      ]
    },
    {
      "pr_number": 8,
      "title": "fix: resolve path traversal vulnerability",
      "html_url": "https://github.com/acme-corp-forks/api-gateway/pull/8",
      "state": "open",
      "merged": false,
      "created_at": "2025-12-02T12:14:00+00:00",
      "repo": "https://github.com/acme-corp-forks/api-gateway",
      "user": "devin-ai-integration[bot]",
      "session_id": "devin-10952715826b44e582cb76ecb0990fe9",
      "issue_ids": [
        "ISSUE-003-001",
        "ISSUE-003-002",
        "ISSUE-003-003"
      ]
    },
    {
      "pr_number": 9,
      "title": "fix: resolve weak crypto vulnerability",
      "html_url": "https://github.com/acme-corp-forks/api-gateway/pull/9",
      "state": "closed",
      "merged": false,
      "created_at": "2025-12-15T08:10:00+00:00",
      "repo": "https://github.com/acme-corp-forks/api-gateway",
      "user": "devin-ai-integration[bot]",
      "session_id": "devin-8cc80e7803a0434ea6397e07fb13122d",
      "issue_ids": [
        "ISSUE-004-001",
        "ISSUE-004-002",
        "ISSUE-004-003",
        "ISSUE-004-004"
      ]
    },
    {
      "pr_number": 10,
      "title": "fix: resolve SSRF vulnerability",
      "html_url": "https://github.com/acme-corp-forks/api-gateway/pull/10",
      "state": "closed",
      "merged": false,
      "created_at": "2026-01-18T18:51:00+00:00",
      "repo": "https://github.com/acme-corp-forks/api-gateway",
      "user": "devin-ai-integration[bot]",
      "session_id": "devin-985f036257684f1f848e055e62c1f965",
      "issue_ids": [
        "ISSUE-007-001",
        "ISSUE-007-002"
      ]
    },
    {
      "pr_number": 11,
      "title": "fix: resolve auth bypass vulnerability",
      "html_url": "https://github.com/acme-corp-forks/mobile-backend/pull/11",
      "state": "closed",
      "merged": true,
      "created_at": "2025-11-03T16:08:00+00:00",
      "repo": "https://github.com/acme-corp-forks/mobile-backend",
      "user": "devin-ai-integration[bot]",
      "session_id": "devin-03a63f5b78fa4951a494f592ecca75b5",
      "issue_ids": [
        "ISSUE-001-005",
        "ISSUE-001-006",
        "ISSUE-001-007",
        "ISSUE-001-008"
      ]
    },
    {
      "pr_number": 12,
      "title": "fix: resolve deserialization vulnerability",
      "html_url": "https://github.com/acme-corp-forks/mobile-backend/pull/12",
      "state": "closed",
      "merged": false,
      "created_at": "2025-11-03T18:25:00+00:00",
      "repo": "https://github.com/acme-corp-forks/mobile-backend",
      "user": "devin-ai-integration[bot]",
      "session_id": "devin-2b68426fb17045cb881af7d51e15180d",
      "issue_ids": [
        "ISSUE-002-001"
      ]
    },
    {
      "pr_number": 13,
      "title": "fix: resolve XSS vulnerability",
      "html_url": "https://github.com/acme-corp-forks/mobile-backend/pull/13",
      "state": "closed",
      "merged": true,
      "created_at": "2025-11-04T09:41:00+00:00",
      "repo": "https://github.com/acme-corp-forks/mobile-backend",
      "user": "devin-ai-integration[bot]",
      "session_id": "devin-6e86ecc7e8014f659f08db54bb94ee07",
      "issue_ids": [
        "ISSUE-003-001",
        "ISSUE-003-002",
        "ISSUE-003-003"
      ]
    },
    {
      "pr_number": 14,
      "title": "fix: resolve auth bypass vulnerability",
      "html_url": "https://github.com/acme-corp-forks/mobile-backend/pull/14",
      "state": "closed",
      "merged": true,
      "created_at": "2026-01-23T07:46:00+00:00",
      "repo": "https://github.com/acme-corp-forks/mobile-backend",
      "user": "devin-ai-integration[bot]",
      "session_id": "devin-d4d84debc820498faa0c4f6cae19eb0a",
      "issue_ids": [
        "ISSUE-008-001",
        "ISSUE-008-002"
      ]
    },
    {
      "pr_number": 15,
      "title": "fix: resolve XSS vulnerability",
      "html_url": "https://github.com/acme-corp-forks/mobile-backend/pull/15",
      "state": "closed",
      "merged": true,
      "created_at": "2026-01-23T08:39:00+00:00",
      "repo": "https://github.com/acme-corp-forks/mobile-backend",
      "user": "devin-ai-integration[bot]",
      "session_id": "devin-65434266c39049d7bf73962b20b73a6a",
      "issue_ids": [
        "ISSUE-009-001"
      ]
    },
    {
      "pr_number": 16,
      "title": "fix: resolve info disclosure vulnerability",
      "html_url": "https://github.com/acme-corp-forks/data-pipeline/pull/16",
      "state": "closed",
      "merged": true,
      "created_at": "2025-11-01T11:05:00+00:00",
      "repo": "https://github.com/acme-corp-forks/data-pipeline",
      "user": "devin-ai-integration[bot]",
      "session_id": "devin-e899a2f0dbf94ae882042fb3d0c46cad",
      "issue_ids": [
        "ISSUE-001-007",
        "ISSUE-001-008",
        "ISSUE-001-009",
        "ISSUE-001-010",
        "ISSUE-001-011",
        "ISSUE-001-012"
      ]
    },
    {
      "pr_number": 17,
      "title": "fix: resolve XSS vulnerability",
      "html_url": "https://github.com/acme-corp-forks/data-pipeline/pull/17",
      "state": "closed",
      "merged": false,
      "created_at": "2025-11-25T16:32:00+00:00",
      "repo": "https://github.com/acme-corp-forks/data-pipeline",
      "user": "devin-ai-integration[bot]",
      "session_id": "devin-c1137c692d384b2ea21575b8c258915b",
      "issue_ids": [
        "ISSUE-003-001",
        "ISSUE-003-002"
      ]
    },
    {
      "pr_number": 18,
      "title": "fix: resolve auth bypass vulnerability",
      "html_url": "https://github.com/acme-corp-forks/data-pipeline/pull/18",
      "state": "closed",
      "merged": true,
      "created_at": "2025-12-24T12:33:00+00:00",
      "repo": "https://github.com/acme-corp-forks/data-pipeline",
      "user": "devin-ai-integration[bot]",
      "session_id": "devin-48337ca2d1e44f1db3f04d6898d7ebd7",
      "issue_ids": [
        "ISSUE-005-001",
        "ISSUE-005-002"
      ]
    },
    {
      "pr_number": 19,
      "title": "fix: resolve weak crypto vulnerability",
      "html_url": "https://github.com/acme-corp-forks/data-pipeline/pull/19",
      "state": "closed",
      "merged": true,
      "created_at": "2026-01-04T11:19:00+00:00",
      "repo": "https://github.com/acme-corp-forks/data-pipeline",
      "user": "devin-ai-integration[bot]",
      "session_id": "devin-f0d64f8ba2764bc8b3c76fc52dcbf2b5",
      "issue_ids": [
        "ISSUE-006-001"
      ]
    },
    {
      "pr_number": 20,
      "title": "fix: resolve XSS vulnerability",
      "html_url": "https://github.com/acme-corp-forks/data-pipeline/pull/20",
      "state": "closed",
      "merged": true,
      "created_at": "2026-01-24T14:44:00+00:00",
      "repo": "https://github.com/acme-corp-forks/data-pipeline",
      "user": "devin-ai-integration[bot]",
      "session_id": "devin-6269a76472584e189eea8ff4ae53bd16",
      "issue_ids": [
        "ISSUE-007-001",
        "ISSUE-007-002"
      ]
    },
    {
      "pr_number": 21,
      "title": "fix: resolve weak crypto vulnerability",
      "html_url": "https://github.com/acme-corp-forks/internal-tools/pull/21",
      "state": "closed",
      "merged": true,
      "created_at": "2025-11-07T18:36:00+00:00",
      "repo": "https://github.com/acme-corp-forks/internal-tools",
      "user": "devin-ai-integration[bot]",
      "session_id": "devin-535bd9e306b34531af61863108a27f1c",
      "issue_ids": [
        "ISSUE-001-009",
        "ISSUE-001-010",
        "ISSUE-001-011",
        "ISSUE-001-012"
      ]
    },
    {
      "pr_number": 22,
      "title": "fix: resolve info disclosure vulnerability",
      "html_url": "https://github.com/acme-corp-forks/internal-tools/pull/22",
      "state": "closed",
      "merged": true,
      "created_at": "2025-12-02T09:19:00+00:00",
      "repo": "https://github.com/acme-corp-forks/internal-tools",
      "user": "devin-ai-integration[bot]",
      "session_id": "devin-1acf0fa3b8264dab8dcb8e4aba52325b",
      "issue_ids": [
        "ISSUE-002-004",
        "ISSUE-002-005",
        "ISSUE-002-006"
      ]
    },
    {
      "pr_number": 23,
      "title": "fix: resolve weak crypto vulnerability",
      "html_url": "https://github.com/acme-corp-forks/internal-tools/pull/23",
      "state": "closed",
      "merged": false,
      "created_at": "2026-01-10T10:17:00+00:00",
      "repo": "https://github.com/acme-corp-forks/internal-tools",
      "user": "devin-ai-integration[bot]",
      "session_id": "devin-c8c1891ba21841dcb67297e495ec4869",
      "issue_ids": [
        "ISSUE-003-001",
        "ISSUE-003-002",
        "ISSUE-003-003"
      ]
    },
    {
      "pr_number": 24,
      "title": "fix: resolve SQL injection vulnerability",
      "html_url": "https://github.com/acme-corp-forks/internal-tools/pull/24",
      "state": "closed",
      "merged": true,
      "created_at": "2026-01-12T10:02:00+00:00",
      "repo": "https://github.com/acme-corp-forks/internal-tools",
      "user": "devin-ai-integration[bot]",
      "session_id": "devin-96f00b606ef548a9a77438db2c1245b4",
      "issue_ids": [
        "ISSUE-004-001"
      ]
    }
  ],
  "verification_records": [
    {
      "pr_url": "https://github.com/acme-corp-forks/web-platform/pull/2",
      "pr_number": 2,
      "session_id": "devin-d39dcf04246b43c496e3a9a6e3db3182",
      "verified_at": "2025-11-12T10:14:00+00:00",
      "label": "verified-fix",
      "summary": {
        "total_targeted": 1,
        "fixed_count": 1,
        "still_present": 0,
        "fix_rate": 100.0
      }
    },
    {
      "pr_url": "https://github.com/acme-corp-forks/web-platform/pull/4",
      "pr_number": 4,
      "session_id": "devin-9df39e5c3ec545369df27a5af9d282ac",
      "verified_at": "2026-01-11T13:45:00+00:00",
      "label": "verified-fix",
      "summary": {
        "total_targeted": 1,
        "fixed_count": 1,
        "still_present": 0,
        "fix_rate": 100.0
      }
    },
    {
      "pr_url": "https://github.com/acme-corp-forks/web-platform/pull/5",
      "pr_number": 5,
      "session_id": "devin-893593661f6e42d388d9fe473574bf55",
      "verified_at": "2026-01-24T05:34:00+00:00",
      "label": "verified-fix",
      "summary": {
        "total_targeted": 1,
        "fixed_count": 1,
        "still_present": 0,
        "fix_rate": 100.0
      }
    },
    {
      "pr_url": "https://github.com/acme-corp-forks/api-gateway/pull/7",
      "pr_number": 7,
      "session_id": "devin-e16017965e8b4462b182d9cc74877071",
      "verified_at": "2025-11-22T01:53:00+00:00",
      "label": "codeql-partial-fix",
      "summary": {
        "total_targeted": 3,
        "fixed_count": 1,
        "still_present": 2,
        "fix_rate": 33.3
      }
    },
    {
      "pr_url": "https://github.com/acme-corp-forks/mobile-backend/pull/11",
      "pr_number": 11,
      "session_id": "devin-03a63f5b78fa4951a494f592ecca75b5",
      "verified_at": "2025-11-03T17:09:00+00:00",
      "label": "codeql-partial-fix",
      "summary": {
        "total_targeted": 4,
        "fixed_count": 3,
        "still_present": 1,
        "fix_rate": 75.0
      }
    },
    {
      "pr_url": "https://github.com/acme-corp-forks/mobile-backend/pull/13",
      "pr_number": 13,
      "session_id": "devin-6e86ecc7e8014f659f08db54bb94ee07",
      "verified_at": "2025-11-04T10:12:00+00:00",
      "label": "codeql-partial-fix",
      "summary": {
        "total_targeted": 3,
        "fixed_count": 1,
        "still_present": 2,
        "fix_rate": 33.3
      }
    },
    {
      "pr_url": "https://github.com/acme-corp-forks/mobile-backend/pull/14",
      "pr_number": 14,
      "session_id": "devin-d4d84debc820498faa0c4f6cae19eb0a",
      "verified_at": "2026-01-23T10:48:00+00:00",
      "label": "codeql-partial-fix",
      "summary": {
        "total_targeted": 2,
        "fixed_count": 1,
        "still_present": 1,
        "fix_rate": 50.0
      }
    },
    {
      "pr_url": "https://github.com/acme-corp-forks/mobile-backend/pull/15",
      "pr_number": 15,
      "session_id": "devin-65434266c39049d7bf73962b20b73a6a",
      "verified_at": "2026-01-23T17:49:00+00:00",
      "label": "verified-fix",
      "summary": {
        "total_targeted": 1,
        "fixed_count": 1,
        "still_present": 0,
        "fix_rate": 100.0
      }
    },
    {
      "pr_url": "https://github.com/acme-corp-forks/data-pipeline/pull/16",
      "pr_number": 16,
      "session_id": "devin-e899a2f0dbf94ae882042fb3d0c46cad",
      "verified_at": "2025-11-01T14:46:00+00:00",
      "label": "codeql-partial-fix",
      "summary": {
        "total_targeted": 6,
        "fixed_count": 4,
        "still_present": 2,
        "fix_rate": 66.7
      }
    },
    {
      "pr_url": "https://github.com/acme-corp-forks/data-pipeline/pull/18",
      "pr_number": 18,
      "session_id": "devin-48337ca2d1e44f1db3f04d6898d7ebd7",
      "verified_at": "2025-12-24T23:59:00+00:00",
      "label": "codeql-partial-fix",
      "summary": {
        "total_targeted": 2,
        "fixed_count": 1,
        "still_present": 1,
        "fix_rate": 50.0
      }
    },
    {
      "pr_url": "https://github.com/acme-corp-forks/data-pipeline/pull/19",
      "pr_number": 19,
      "session_id": "devin-f0d64f8ba2764bc8b3c76fc52dcbf2b5",
      "verified_at": "2026-01-04T14:52:00+00:00",
      "label": "verified-fix",
      "summary": {
        "total_targeted": 1,
        "fixed_count": 1,
        "still_present": 0,
        "fix_rate": 100.0
      }
    },
    {
      "pr_url": "https://github.com/acme-corp-forks/data-pipeline/pull/20",
      "pr_number": 20,
      "session_id": "devin-6269a76472584e189eea8ff4ae53bd16",
      "verified_at": "2026-01-24T18:55:00+00:00",
      "label": "codeql-partial-fix",
      "summary": {
        "total_targeted": 2,
        "fixed_count": 1,
        "still_present": 1,
        "fix_rate": 50.0
      }
    },
    {
      "pr_url": "https://github.com/acme-corp-forks/internal-tools/pull/21",
      "pr_number": 21,
      "session_id": "devin-535bd9e306b34531af61863108a27f1c",
      "verified_at": "2025-11-07T19:21:00+00:00",
      "label": "codeql-partial-fix",
      "summary": {
        "total_targeted": 4,
        "fixed_count": 3,
        "still_present": 1,
        "fix_rate": 75.0
      }
    },
    {
      "pr_url": "https://github.com/acme-corp-forks/internal-tools/pull/22",
      "pr_number": 22,
      "session_id": "devin-1acf0fa3b8264dab8dcb8e4aba52325b",
      "verified_at": "2025-12-02T11:50:00+00:00",
      "label": "codeql-partial-fix",
      "summary": {
        "total_targeted": 3,
        "fixed_count": 2,
        "still_present": 1,
        "fix_rate": 66.7
      }
    },
    {
      "pr_url": "https://github.com/acme-corp-forks/internal-tools/pull/24",
      "pr_number": 24,
      "session_id": "devin-96f00b606ef548a9a77438db2c1245b4",
      "verified_at": "2026-01-12T15:04:00+00:00",
      "label": "verified-fix",
      "summary": {
        "total_targeted": 1,
        "fixed_count": 1,
        "still_present": 0,
        "fix_rate": 100.0
      }
    }
  ],
  "orchestrator_state": {
    "last_cycle": "2026-01-25T07:36:00+00:00",
    "rate_limiter": {
      "created_timestamps": [
        "2026-01-24T13:55:00+00:00",
        "2025-11-07T18:21:00+00:00",
        "2025-11-07T18:21:00+00:00",
        "2025-11-07T18:21:00+00:00",
        "2025-12-02T08:50:00+00:00",
        "2025-12-02T08:50:00+00:00",
        "2026-01-10T09:37:00+00:00",
        "2026-01-12T09:04:00+00:00"
      ]
    },
    "dispatch_history": {
      "aff2b6eb094e4c93ec139cdf6bd08376": [
        {
          "session_id": "devin-dd1006b888cd41edaf56adb1ed1acfd3",
          "session_url": "https://app.devin.ai/sessions/dd1006b888cd41edaf56adb1ed1acfd3",
          "dispatched_at": "2025-11-04T17:17:00+00:00",
          "status": "finished",
          "pr_url": "https://github.com/acme-corp-forks/web-platform/pull/1"
        },
        {
          "session_id": "devin-935ef7725ad24eaa85510b2cf5f13ba4",
          "session_url": "https://app.devin.ai/sessions/935ef7725ad24eaa85510b2cf5f13ba4",
          "dispatched_at": "2025-11-10T14:13:00+00:00",
          "status": "finished",
          "pr_url": "https://github.com/acme-corp-forks/api-gateway/pull/6"
        },
        {
          "session_id": "devin-a26d1ab12dda44d6a6260a1540a84c25",
          "session_url": "https://app.devin.ai/sessions/a26d1ab12dda44d6a6260a1540a84c25",
          "dispatched_at": "2025-11-03T15:09:00+00:00",
          "status": "stopped",
          "pr_url": ""
        },
        {
          "session_id": "devin-eeb6ad185681444c8c1cd3e7ea6ad337",
          "session_url": "https://app.devin.ai/sessions/eeb6ad185681444c8c1cd3e7ea6ad337",
          "dispatched_at": "2025-11-01T10:46:00+00:00",
          "status": "stopped",
          "pr_url": ""
        },
        {
          "session_id": "devin-ddeed815337f423b8b474f90ed35873d",
          "session_url": "https://app.devin.ai/sessions/ddeed815337f423b8b474f90ed35873d",
          "dispatched_at": "2025-11-07T18:21:00+00:00",
          "status": "error",
          "pr_url": ""
        }
      ],
      "785f8bfc58fb678ca29c8eadd71d276c": [
        {
          "session_id": "devin-dd1006b888cd41edaf56adb1ed1acfd3",
          "session_url": "https://app.devin.ai/sessions/dd1006b888cd41edaf56adb1ed1acfd3",
          "dispatched_at": "2025-11-04T17:17:00+00:00",
          "status": "finished",
          "pr_url": "https://github.com/acme-corp-forks/web-platform/pull/1"
        },
        {
          "session_id": "devin-935ef7725ad24eaa85510b2cf5f13ba4",
          "session_url": "https://app.devin.ai/sessions/935ef7725ad24eaa85510b2cf5f13ba4",
          "dispatched_at": "2025-11-10T14:13:00+00:00",
          "status": "finished",
          "pr_url": "https://github.com/acme-corp-forks/api-gateway/pull/6"
        },
        {
          "session_id": "devin-a26d1ab12dda44d6a6260a1540a84c25",
          "session_url": "https://app.devin.ai/sessions/a26d1ab12dda44d6a6260a1540a84c25",
          "dispatched_at": "2025-11-03T15:09:00+00:00",
          "status": "stopped",
          "pr_url": ""
        },
        {
          "session_id": "devin-eeb6ad185681444c8c1cd3e7ea6ad337",
          "session_url": "https://app.devin.ai/sessions/eeb6ad185681444c8c1cd3e7ea6ad337",
          "dispatched_at": "2025-11-01T10:46:00+00:00",
          "status": "stopped",
          "pr_url": ""
        },
        {
          "session_id": "devin-ddeed815337f423b8b474f90ed35873d",
          "session_url": "https://app.devin.ai/sessions/ddeed815337f423b8b474f90ed35873d",
          "dispatched_at": "2025-11-07T18:21:00+00:00",
          "status": "error",
          "pr_url": ""
        }
      ],
      "d81b6e3203835164b928e9d21cc23999": [
        {
          "session_id": "devin-dd1006b888cd41edaf56adb1ed1acfd3",
          "session_url": "https://app.devin.ai/sessions/dd1006b888cd41edaf56adb1ed1acfd3",
          "dispatched_at": "2025-11-04T17:17:00+00:00",
          "status": "finished",
          "pr_url": "https://github.com/acme-corp-forks/web-platform/pull/1"
        },
        {
          "session_id": "devin-935ef7725ad24eaa85510b2cf5f13ba4",
          "session_url": "https://app.devin.ai/sessions/935ef7725ad24eaa85510b2cf5f13ba4",
          "dispatched_at": "2025-11-10T14:13:00+00:00",
          "status": "finished",
          "pr_url": "https://github.com/acme-corp-forks/api-gateway/pull/6"
        },
        {
          "session_id": "devin-a26d1ab12dda44d6a6260a1540a84c25",
          "session_url": "https://app.devin.ai/sessions/a26d1ab12dda44d6a6260a1540a84c25",
          "dispatched_at": "2025-11-03T15:09:00+00:00",
          "status": "stopped",
          "pr_url": ""
        },
        {
          "session_id": "devin-eeb6ad185681444c8c1cd3e7ea6ad337",
          "session_url": "https://app.devin.ai/sessions/eeb6ad185681444c8c1cd3e7ea6ad337",
          "dispatched_at": "2025-11-01T10:46:00+00:00",
          "status": "stopped",
          "pr_url": ""
        },
        {
          "session_id": "devin-ddeed815337f423b8b474f90ed35873d",
          "session_url": "https://app.devin.ai/sessions/ddeed815337f423b8b474f90ed35873d",
          "dispatched_at": "2025-11-07T18:21:00+00:00",
          "status": "error",
          "pr_url": ""
        }
      ],
      "e7a01da58d71d5f160791439a891d8b6": [
        {
          "session_id": "devin-d17b1c0d0bc84abeb6598e5a7f9e173a",
          "session_url": "https://app.devin.ai/sessions/d17b1c0d0bc84abeb6598e5a7f9e173a",
          "dispatched_at": "2025-11-04T17:17:00+00:00",
          "status": "stopped",
          "pr_url": ""
        },
        {
          "session_id": "devin-935ef7725ad24eaa85510b2cf5f13ba4",
          "session_url": "https://app.devin.ai/sessions/935ef7725ad24eaa85510b2cf5f13ba4",
          "dispatched_at": "2025-11-10T14:13:00+00:00",
          "status": "finished",
          "pr_url": "https://github.com/acme-corp-forks/api-gateway/pull/6"
        },
        {
          "session_id": "devin-a26d1ab12dda44d6a6260a1540a84c25",
          "session_url": "https://app.devin.ai/sessions/a26d1ab12dda44d6a6260a1540a84c25",
          "dispatched_at": "2025-11-03T15:09:00+00:00",
          "status": "stopped",
          "pr_url": ""
        },
        {
          "session_id": "devin-eeb6ad185681444c8c1cd3e7ea6ad337",
          "session_url": "https://app.devin.ai/sessions/eeb6ad185681444c8c1cd3e7ea6ad337",
          "dispatched_at": "2025-11-01T10:46:00+00:00",
          "status": "stopped",
          "pr_url": ""
        },
        {
          "session_id": "devin-ddeed815337f423b8b474f90ed35873d",
          "session_url": "https://app.devin.ai/sessions/ddeed815337f423b8b474f90ed35873d",
          "dispatched_at": "2025-11-07T18:21:00+00:00",
          "status": "error",
          "pr_url": ""
        }
      ],
      "8d52ddb86f36354dfbbefdfb2064c295": [
        {
          "session_id": "devin-d17b1c0d0bc84abeb6598e5a7f9e173a",
          "session_url": "https://app.devin.ai/sessions/d17b1c0d0bc84abeb6598e5a7f9e173a",
          "dispatched_at": "2025-11-04T17:17:00+00:00",
          "status": "stopped",
          "pr_url": ""
        },
        {
          "session_id": "devin-3de4783341ab48de9a30845bbc3500a5",
          "session_url": "https://app.devin.ai/sessions/3de4783341ab48de9a30845bbc3500a5",
          "dispatched_at": "2025-11-10T14:13:00+00:00",
          "status": "stopped",
          "pr_url": ""
        },
        {
          "session_id": "devin-03a63f5b78fa4951a494f592ecca75b5",
          "session_url": "https://app.devin.ai/sessions/03a63f5b78fa4951a494f592ecca75b5",
          "dispatched_at": "2025-11-03T15:09:00+00:00",
          "status": "finished",
          "pr_url": "https://github.com/acme-corp-forks/mobile-backend/pull/11"
        },
        {
          "session_id": "devin-eeb6ad185681444c8c1cd3e7ea6ad337",
          "session_url": "https://app.devin.ai/sessions/eeb6ad185681444c8c1cd3e7ea6ad337",
          "dispatched_at": "2025-11-01T10:46:00+00:00",
          "status": "stopped",
          "pr_url": ""
        },
        {
          "session_id": "devin-afd8f02506ba45f7a491e5dae92ba840",
          "session_url": "https://app.devin.ai/sessions/afd8f02506ba45f7a491e5dae92ba840",
          "dispatched_at": "2025-11-07T18:21:00+00:00",
          "status": "stopped",
          "pr_url": ""
        }
      ],
      "82a6f9cb96f1e8f9a94ba3ccc972b258": [
        {
          "session_id": "devin-d17b1c0d0bc84abeb6598e5a7f9e173a",
          "session_url": "https://app.devin.ai/sessions/d17b1c0d0bc84abeb6598e5a7f9e173a",
          "dispatched_at": "2025-11-04T17:17:00+00:00",
          "status": "stopped",
          "pr_url": ""
        },
        {
          "session_id": "devin-3de4783341ab48de9a30845bbc3500a5",
          "session_url": "https://app.devin.ai/sessions/3de4783341ab48de9a30845bbc3500a5",
          "dispatched_at": "2025-11-10T14:13:00+00:00",
          "status": "stopped",
          "pr_url": ""
        },
        {
          "session_id": "devin-03a63f5b78fa4951a494f592ecca75b5",
          "session_url": "https://app.devin.ai/sessions/03a63f5b78fa4951a494f592ecca75b5",
          "dispatched_at": "2025-11-03T15:09:00+00:00",
          "status": "finished",
          "pr_url": "https://github.com/acme-corp-forks/mobile-backend/pull/11"
        },
        {
          "session_id": "devin-eeb6ad185681444c8c1cd3e7ea6ad337",
          "session_url": "https://app.devin.ai/sessions/eeb6ad185681444c8c1cd3e7ea6ad337",
          "dispatched_at": "2025-11-01T10:46:00+00:00",
          "status": "stopped",
          "pr_url": ""
        },
        {
          "session_id": "devin-afd8f02506ba45f7a491e5dae92ba840",
          "session_url": "https://app.devin.ai/sessions/afd8f02506ba45f7a491e5dae92ba840",
          "dispatched_at": "2025-11-07T18:21:00+00:00",
          "status": "stopped",
          "pr_url": ""
        }
      ],
      "e556ac909b828cc174f253ae43eba28a": [
        {
          "session_id": "devin-d7092aa13d7c4f19857eac9bc1bfad8f",
          "session_url": "https://app.devin.ai/sessions/d7092aa13d7c4f19857eac9bc1bfad8f",
          "dispatched_at": "2025-11-04T17:17:00+00:00",
          "status": "stopped",
          "pr_url": ""
        },
        {
          "session_id": "devin-3de4783341ab48de9a30845bbc3500a5",
          "session_url": "https://app.devin.ai/sessions/3de4783341ab48de9a30845bbc3500a5",
          "dispatched_at": "2025-11-10T14:13:00+00:00",
          "status": "stopped",
          "pr_url": ""
        },
        {
          "session_id": "devin-03a63f5b78fa4951a494f592ecca75b5",
          "session_url": "https://app.devin.ai/sessions/03a63f5b78fa4951a494f592ecca75b5",
          "dispatched_at": "2025-11-03T15:09:00+00:00",
          "status": "finished",
          "pr_url": "https://github.com/acme-corp-forks/mobile-backend/pull/11"
        },
        {
          "session_id": "devin-e899a2f0dbf94ae882042fb3d0c46cad",
          "session_url": "https://app.devin.ai/sessions/e899a2f0dbf94ae882042fb3d0c46cad",
          "dispatched_at": "2025-11-01T10:46:00+00:00",
          "status": "finished",
          "pr_url": "https://github.com/acme-corp-forks/data-pipeline/pull/16"
        },
        {
          "session_id": "devin-afd8f02506ba45f7a491e5dae92ba840",
          "session_url": "https://app.devin.ai/sessions/afd8f02506ba45f7a491e5dae92ba840",
          "dispatched_at": "2025-11-07T18:21:00+00:00",
          "status": "stopped",
          "pr_url": ""
        }
      ],
      "1c5a8076193dc7bccc5f62ea21c3d437": [
        {
          "session_id": "devin-d7092aa13d7c4f19857eac9bc1bfad8f",
          "session_url": "https://app.devin.ai/sessions/d7092aa13d7c4f19857eac9bc1bfad8f",
          "dispatched_at": "2025-11-04T17:17:00+00:00",
          "status": "stopped",
          "pr_url": ""
        },
        {
          "session_id": "devin-3de4783341ab48de9a30845bbc3500a5",
          "session_url": "https://app.devin.ai/sessions/3de4783341ab48de9a30845bbc3500a5",
          "dispatched_at": "2025-11-10T14:13:00+00:00",
          "status": "stopped",
          "pr_url": ""
        },
        {
          "session_id": "devin-03a63f5b78fa4951a494f592ecca75b5",
          "session_url": "https://app.devin.ai/sessions/03a63f5b78fa4951a494f592ecca75b5",
          "dispatched_at": "2025-11-03T15:09:00+00:00",
          "status": "finished",
          "pr_url": "https://github.com/acme-corp-forks/mobile-backend/pull/11"
        },
        {
          "session_id": "devin-e899a2f0dbf94ae882042fb3d0c46cad",
          "session_url": "https://app.devin.ai/sessions/e899a2f0dbf94ae882042fb3d0c46cad",
          "dispatched_at": "2025-11-01T10:46:00+00:00",
          "status": "finished",
          "pr_url": "https://github.com/acme-corp-forks/data-pipeline/pull/16"
        },
        {
          "session_id": "devin-afd8f02506ba45f7a491e5dae92ba840",
          "session_url": "https://app.devin.ai/sessions/afd8f02506ba45f7a491e5dae92ba840",
          "dispatched_at": "2025-11-07T18:21:00+00:00",
          "status": "stopped",
          "pr_url": ""
        }
      ],
      "df92a3d9aea3e7ea72ba914ae5ac3bee": [
        {
          "session_id": "devin-d7092aa13d7c4f19857eac9bc1bfad8f",
          "session_url": "https://app.devin.ai/sessions/d7092aa13d7c4f19857eac9bc1bfad8f",
          "dispatched_at": "2025-11-04T17:17:00+00:00",
          "status": "stopped",
          "pr_url": ""
        },
        {
          "session_id": "devin-a439fe6dd3e942149ade722cfeda7cdc",
          "session_url": "https://app.devin.ai/sessions/a439fe6dd3e942149ade722cfeda7cdc",
          "dispatched_at": "2025-11-10T14:13:00+00:00",
          "status": "error",
          "pr_url": ""
        },
        {
          "session_id": "devin-736d1924f1354448bf1070e2bc499f75",
          "session_url": "https://app.devin.ai/sessions/736d1924f1354448bf1070e2bc499f75",
          "dispatched_at": "2025-11-03T15:09:00+00:00",
          "status": "stopped",
          "pr_url": ""
        },
        {
          "session_id": "devin-e899a2f0dbf94ae882042fb3d0c46cad",
          "session_url": "https://app.devin.ai/sessions/e899a2f0dbf94ae882042fb3d0c46cad",
          "dispatched_at": "2025-11-01T10:46:00+00:00",
          "status": "finished",
          "pr_url": "https://github.com/acme-corp-forks/data-pipeline/pull/16"
        },
        {
          "session_id": "devin-535bd9e306b34531af61863108a27f1c",
          "session_url": "https://app.devin.ai/sessions/535bd9e306b34531af61863108a27f1c",
          "dispatched_at": "2025-11-07T18:21:00+00:00",
          "status": "finished",
          "pr_url": "https://github.com/acme-corp-forks/internal-tools/pull/21"
        }
      ],
      "b79de670ea501b8e11db7d65d2150d4d": [
        {
          "session_id": "devin-b0d8c42740904edf93a79ec175364837",
          "session_url": "https://app.devin.ai/sessions/b0d8c42740904edf93a79ec175364837",
          "dispatched_at": "2025-11-04T17:17:00+00:00",
          "status": "finished",
          "pr_url": ""
        },
        {
          "session_id": "devin-a439fe6dd3e942149ade722cfeda7cdc",
          "session_url": "https://app.devin.ai/sessions/a439fe6dd3e942149ade722cfeda7cdc",
          "dispatched_at": "2025-11-10T14:13:00+00:00",
          "status": "error",
          "pr_url": ""
        },
        {
          "session_id": "devin-736d1924f1354448bf1070e2bc499f75",
          "session_url": "https://app.devin.ai/sessions/736d1924f1354448bf1070e2bc499f75",
          "dispatched_at": "2025-11-03T15:09:00+00:00",
          "status": "stopped",
          "pr_url": ""
        },
        {
          "session_id": "devin-e899a2f0dbf94ae882042fb3d0c46cad",
          "session_url": "https://app.devin.ai/sessions/e899a2f0dbf94ae882042fb3d0c46cad",
          "dispatched_at": "2025-11-01T10:46:00+00:00",
          "status": "finished",
          "pr_url": "https://github.com/acme-corp-forks/data-pipeline/pull/16"
        },
        {
          "session_id": "devin-535bd9e306b34531af61863108a27f1c",
          "session_url": "https://app.devin.ai/sessions/535bd9e306b34531af61863108a27f1c",
          "dispatched_at": "2025-11-07T18:21:00+00:00",
          "status": "finished",
          "pr_url": "https://github.com/acme-corp-forks/internal-tools/pull/21"
        }
      ],
      "5ff3ed94cd635000f6de902a539a577d": [
        {
          "session_id": "devin-b0d8c42740904edf93a79ec175364837",
          "session_url": "https://app.devin.ai/sessions/b0d8c42740904edf93a79ec175364837",
          "dispatched_at": "2025-11-04T17:17:00+00:00",
          "status": "finished",
          "pr_url": ""
        },
        {
          "session_id": "devin-a439fe6dd3e942149ade722cfeda7cdc",
          "session_url": "https://app.devin.ai/sessions/a439fe6dd3e942149ade722cfeda7cdc",
          "dispatched_at": "2025-11-10T14:13:00+00:00",
          "status": "error",
          "pr_url": ""
        },
        {
          "session_id": "devin-736d1924f1354448bf1070e2bc499f75",
          "session_url": "https://app.devin.ai/sessions/736d1924f1354448bf1070e2bc499f75",
          "dispatched_at": "2025-11-03T15:09:00+00:00",
          "status": "stopped",
          "pr_url": ""
        },
        {
          "session_id": "devin-e899a2f0dbf94ae882042fb3d0c46cad",
          "session_url": "https://app.devin.ai/sessions/e899a2f0dbf94ae882042fb3d0c46cad",
          "dispatched_at": "2025-11-01T10:46:00+00:00",
          "status": "finished",
          "pr_url": "https://github.com/acme-corp-forks/data-pipeline/pull/16"
        },
        {
          "session_id": "devin-535bd9e306b34531af61863108a27f1c",
          "session_url": "https://app.devin.ai/sessions/535bd9e306b34531af61863108a27f1c",
          "dispatched_at": "2025-11-07T18:21:00+00:00",
          "status": "finished",
          "pr_url": "https://github.com/acme-corp-forks/internal-tools/pull/21"
        }
      ],
      "e13b7596c57ea51b6063494e1e2383aa": [
        {
          "session_id": "devin-b0d8c42740904edf93a79ec175364837",
          "session_url": "https://app.devin.ai/sessions/b0d8c42740904edf93a79ec175364837",
          "dispatched_at": "2025-11-04T17:17:00+00:00",
          "status": "finished",
          "pr_url": ""
        },
        {
          "session_id": "devin-a439fe6dd3e942149ade722cfeda7cdc",
          "session_url": "https://app.devin.ai/sessions/a439fe6dd3e942149ade722cfeda7cdc",
          "dispatched_at": "2025-11-10T14:13:00+00:00",
          "status": "error",
          "pr_url": ""
        },
        {
          "session_id": "devin-736d1924f1354448bf1070e2bc499f75",
          "session_url": "https://app.devin.ai/sessions/736d1924f1354448bf1070e2bc499f75",
          "dispatched_at": "2025-11-03T15:09:00+00:00",
          "status": "stopped",
          "pr_url": ""
        },
        {
          "session_id": "devin-e899a2f0dbf94ae882042fb3d0c46cad",
          "session_url": "https://app.devin.ai/sessions/e899a2f0dbf94ae882042fb3d0c46cad",
          "dispatched_at": "2025-11-01T10:46:00+00:00",
          "status": "finished",
          "pr_url": "https://github.com/acme-corp-forks/data-pipeline/pull/16"
        },
        {
          "session_id": "devin-535bd9e306b34531af61863108a27f1c",
          "session_url": "https://app.devin.ai/sessions/535bd9e306b34531af61863108a27f1c",
          "dispatched_at": "2025-11-07T18:21:00+00:00",
          "status": "finished",
          "pr_url": "https://github.com/acme-corp-forks/internal-tools/pull/21"
        }
      ],
      "4bfd6d0e3e153e967c873879d03b8d6f": [
        {
          "session_id": "devin-d39dcf04246b43c496e3a9a6e3db3182",
          "session_url": "https://app.devin.ai/sessions/d39dcf04246b43c496e3a9a6e3db3182",
          "dispatched_at": "2025-11-12T09:14:00+00:00",
          "status": "finished",
          "pr_url": "https://github.com/acme-corp-forks/web-platform/pull/2"
        },
        {
          "session_id": "devin-e16017965e8b4462b182d9cc74877071",
          "session_url": "https://app.devin.ai/sessions/e16017965e8b4462b182d9cc74877071",
          "dispatched_at": "2025-11-21T13:53:00+00:00",
          "status": "finished",
          "pr_url": "https://github.com/acme-corp-forks/api-gateway/pull/7"
        },
        {
          "session_id": "devin-2b68426fb17045cb881af7d51e15180d",
          "session_url": "https://app.devin.ai/sessions/2b68426fb17045cb881af7d51e15180d",
          "dispatched_at": "2025-11-03T17:34:00+00:00",
          "status": "finished",
          "pr_url": "https://github.com/acme-corp-forks/mobile-backend/pull/12"
        },
        {
          "session_id": "devin-e535bbf37fd041ab8f37f662724104eb",
          "session_url": "https://app.devin.ai/sessions/e535bbf37fd041ab8f37f662724104eb",
          "dispatched_at": "2025-11-18T07:17:00+00:00",
          "status": "finished",
          "pr_url": ""
        },
        {
          "session_id": "devin-99baaaf538eb415aa867279ef2e8d6ff",
          "session_url": "https://app.devin.ai/sessions/99baaaf538eb415aa867279ef2e8d6ff",
          "dispatched_at": "2025-12-02T08:50:00+00:00",
          "status": "finished",
          "pr_url": ""
        }
      ],
      "6de20545a18c43f8fe3ebfdae6777436": [
        {
          "session_id": "devin-54b58a7a5e4d47fba639e17d3a7cf36a",
          "session_url": "https://app.devin.ai/sessions/54b58a7a5e4d47fba639e17d3a7cf36a",
          "dispatched_at": "2025-11-14T16:47:00+00:00",
          "status": "stopped",
          "pr_url": ""
        },
        {
          "session_id": "devin-10952715826b44e582cb76ecb0990fe9",
          "session_url": "https://app.devin.ai/sessions/10952715826b44e582cb76ecb0990fe9",
          "dispatched_at": "2025-12-02T11:18:00+00:00",
          "status": "finished",
          "pr_url": "https://github.com/acme-corp-forks/api-gateway/pull/8"
        },
        {
          "session_id": "devin-6e86ecc7e8014f659f08db54bb94ee07",
          "session_url": "https://app.devin.ai/sessions/6e86ecc7e8014f659f08db54bb94ee07",
          "dispatched_at": "2025-11-04T09:12:00+00:00",
          "status": "finished",
          "pr_url": "https://github.com/acme-corp-forks/mobile-backend/pull/13"
        },
        {
          "session_id": "devin-c1137c692d384b2ea21575b8c258915b",
          "session_url": "https://app.devin.ai/sessions/c1137c692d384b2ea21575b8c258915b",
          "dispatched_at": "2025-11-25T15:32:00+00:00",
          "status": "finished",
          "pr_url": "https://github.com/acme-corp-forks/data-pipeline/pull/17"
        },
        {
          "session_id": "devin-c8c1891ba21841dcb67297e495ec4869",
          "session_url": "https://app.devin.ai/sessions/c8c1891ba21841dcb67297e495ec4869",
          "dispatched_at": "2026-01-10T09:37:00+00:00",
          "status": "finished",
          "pr_url": "https://github.com/acme-corp-forks/internal-tools/pull/23"
        }
      ],
      "ece595768c1b53a42fb299905899da57": [
        {
          "session_id": "devin-54b58a7a5e4d47fba639e17d3a7cf36a",
          "session_url": "https://app.devin.ai/sessions/54b58a7a5e4d47fba639e17d3a7cf36a",
          "dispatched_at": "2025-11-14T16:47:00+00:00",
          "status": "stopped",
          "pr_url": ""
        },
        {
          "session_id": "devin-10952715826b44e582cb76ecb0990fe9",
          "session_url": "https://app.devin.ai/sessions/10952715826b44e582cb76ecb0990fe9",
          "dispatched_at": "2025-12-02T11:18:00+00:00",
          "status": "finished",
          "pr_url": "https://github.com/acme-corp-forks/api-gateway/pull/8"
        },
        {
          "session_id": "devin-6e86ecc7e8014f659f08db54bb94ee07",
          "session_url": "https://app.devin.ai/sessions/6e86ecc7e8014f659f08db54bb94ee07",
          "dispatched_at": "2025-11-04T09:12:00+00:00",
          "status": "finished",
          "pr_url": "https://github.com/acme-corp-forks/mobile-backend/pull/13"
        },
        {
          "session_id": "devin-c1137c692d384b2ea21575b8c258915b",
          "session_url": "https://app.devin.ai/sessions/c1137c692d384b2ea21575b8c258915b",
          "dispatched_at": "2025-11-25T15:32:00+00:00",
          "status": "finished",
          "pr_url": "https://github.com/acme-corp-forks/data-pipeline/pull/17"
        },
        {
          "session_id": "devin-c8c1891ba21841dcb67297e495ec4869",
          "session_url": "https://app.devin.ai/sessions/c8c1891ba21841dcb67297e495ec4869",
          "dispatched_at": "2026-01-10T09:37:00+00:00",
          "status": "finished",
          "pr_url": "https://github.com/acme-corp-forks/internal-tools/pull/23"
        }
      ],
      "c4a36be489f993b449dd48b774c19a5a": [
        {
          "session_id": "devin-f83e2e4fc5644e708c852496dd83c469",
          "session_url": "https://app.devin.ai/sessions/f83e2e4fc5644e708c852496dd83c469",
          "dispatched_at": "2025-12-02T09:08:00+00:00",
          "status": "finished",
          "pr_url": ""
        },
        {
          "session_id": "devin-8cc80e7803a0434ea6397e07fb13122d",
          "session_url": "https://app.devin.ai/sessions/8cc80e7803a0434ea6397e07fb13122d",
          "dispatched_at": "2025-12-15T07:56:00+00:00",
          "status": "finished",
          "pr_url": "https://github.com/acme-corp-forks/api-gateway/pull/9"
        },
        {
          "session_id": "devin-dfd42428b7a64809944192741b48ae31",
          "session_url": "https://app.devin.ai/sessions/dfd42428b7a64809944192741b48ae31",
          "dispatched_at": "2025-11-07T11:14:00+00:00",
          "status": "stopped",
          "pr_url": ""
        },
        {
          "session_id": "devin-94725e93cba240db912d8f9ca1bed863",
          "session_url": "https://app.devin.ai/sessions/94725e93cba240db912d8f9ca1bed863",
          "dispatched_at": "2025-12-09T15:37:00+00:00",
          "status": "finished",
          "pr_url": ""
        },
        {
          "session_id": "devin-96f00b606ef548a9a77438db2c1245b4",
          "session_url": "https://app.devin.ai/sessions/96f00b606ef548a9a77438db2c1245b4",
          "dispatched_at": "2026-01-12T09:04:00+00:00",
          "status": "finished",
          "pr_url": "https://github.com/acme-corp-forks/internal-tools/pull/24"
        }
      ],
      "c98d9af4e958ce900d1e019322541b2e": [
        {
          "session_id": "devin-f83e2e4fc5644e708c852496dd83c469",
          "session_url": "https://app.devin.ai/sessions/f83e2e4fc5644e708c852496dd83c469",
          "dispatched_at": "2025-12-02T09:08:00+00:00",
          "status": "finished",
          "pr_url": ""
        },
        {
          "session_id": "devin-8cc80e7803a0434ea6397e07fb13122d",
          "session_url": "https://app.devin.ai/sessions/8cc80e7803a0434ea6397e07fb13122d",
          "dispatched_at": "2025-12-15T07:56:00+00:00",
          "status": "finished",
          "pr_url": "https://github.com/acme-corp-forks/api-gateway/pull/9"
        },
        {
          "session_id": "devin-dfd42428b7a64809944192741b48ae31",
          "session_url": "https://app.devin.ai/sessions/dfd42428b7a64809944192741b48ae31",
          "dispatched_at": "2025-11-07T11:14:00+00:00",
          "status": "stopped",
          "pr_url": ""
        },
        {
          "session_id": "devin-94725e93cba240db912d8f9ca1bed863",
          "session_url": "https://app.devin.ai/sessions/94725e93cba240db912d8f9ca1bed863",
          "dispatched_at": "2025-12-09T15:37:00+00:00",
          "status": "finished",
          "pr_url": ""
        }
      ],
      "33b0be923e253cedc58573d16528b22f": [
        {
          "session_id": "devin-1bee98ed71ae4fda8bd91310ecf6d964",
          "session_url": "https://app.devin.ai/sessions/1bee98ed71ae4fda8bd91310ecf6d964",
          "dispatched_at": "2025-12-02T09:08:00+00:00",
          "status": "stopped",
          "pr_url": ""
        },
        {
          "session_id": "devin-8cc80e7803a0434ea6397e07fb13122d",
          "session_url": "https://app.devin.ai/sessions/8cc80e7803a0434ea6397e07fb13122d",
          "dispatched_at": "2025-12-15T07:56:00+00:00",
          "status": "finished",
          "pr_url": "https://github.com/acme-corp-forks/api-gateway/pull/9"
        },
        {
          "session_id": "devin-dfd42428b7a64809944192741b48ae31",
          "session_url": "https://app.devin.ai/sessions/dfd42428b7a64809944192741b48ae31",
          "dispatched_at": "2025-11-07T11:14:00+00:00",
          "status": "stopped",
          "pr_url": ""
        }
      ],
      "4408bd8d068ee8dcbe36f8b55d996117": [
        {
          "session_id": "devin-1bee98ed71ae4fda8bd91310ecf6d964",
          "session_url": "https://app.devin.ai/sessions/1bee98ed71ae4fda8bd91310ecf6d964",
          "dispatched_at": "2025-12-02T09:08:00+00:00",
          "status": "stopped",
          "pr_url": ""
        },
        {
          "session_id": "devin-8cc80e7803a0434ea6397e07fb13122d",
          "session_url": "https://app.devin.ai/sessions/8cc80e7803a0434ea6397e07fb13122d",
          "dispatched_at": "2025-12-15T07:56:00+00:00",
          "status": "finished",
          "pr_url": "https://github.com/acme-corp-forks/api-gateway/pull/9"
        }
      ],
      "38ead7a1c7c4cdd7cd9f19bc9920f513": [
        {
          "session_id": "devin-15b7ef03472246b9aac2e091909c39c5",
          "session_url": "https://app.devin.ai/sessions/15b7ef03472246b9aac2e091909c39c5",
          "dispatched_at": "2025-12-24T09:28:00+00:00",
          "status": "finished",
          "pr_url": "https://github.com/acme-corp-forks/web-platform/pull/3"
        },
        {
          "session_id": "devin-0010381c6c884501b736a66257c4bf3e",
          "session_url": "https://app.devin.ai/sessions/0010381c6c884501b736a66257c4bf3e",
          "dispatched_at": "2026-01-04T10:08:00+00:00",
          "status": "finished",
          "pr_url": ""
        },
        {
          "session_id": "devin-7884b76197264bfa95990f4edcb553f8",
          "session_url": "https://app.devin.ai/sessions/7884b76197264bfa95990f4edcb553f8",
          "dispatched_at": "2025-11-28T13:44:00+00:00",
          "status": "finished",
          "pr_url": ""
        },
        {
          "session_id": "devin-48337ca2d1e44f1db3f04d6898d7ebd7",
          "session_url": "https://app.devin.ai/sessions/48337ca2d1e44f1db3f04d6898d7ebd7",
          "dispatched_at": "2025-12-24T11:59:00+00:00",
          "status": "finished",
          "pr_url": "https://github.com/acme-corp-forks/data-pipeline/pull/18"
        }
      ],
      "0f981d9e1ba6803f9b3098b8e0e74723": [
        {
          "session_id": "devin-a4c2eb682d964416a37e8799140770a9",
          "session_url": "https://app.devin.ai/sessions/a4c2eb682d964416a37e8799140770a9",
          "dispatched_at": "2025-12-25T06:01:00+00:00",
          "status": "error",
          "pr_url": ""
        },
        {
          "session_id": "devin-f47947c207284669b16e3f1efabce5a8",
          "session_url": "https://app.devin.ai/sessions/f47947c207284669b16e3f1efabce5a8",
          "dispatched_at": "2026-01-09T17:19:00+00:00",
          "status": "stopped",
          "pr_url": ""
        },
        {
          "session_id": "devin-b178e79f6b9046f7a7d6699484db963e",
          "session_url": "https://app.devin.ai/sessions/b178e79f6b9046f7a7d6699484db963e",
          "dispatched_at": "2025-12-01T08:30:00+00:00",
          "status": "finished",
          "pr_url": ""
        },
        {
          "session_id": "devin-f0d64f8ba2764bc8b3c76fc52dcbf2b5",
          "session_url": "https://app.devin.ai/sessions/f0d64f8ba2764bc8b3c76fc52dcbf2b5",
          "dispatched_at": "2026-01-04T10:52:00+00:00",
          "status": "finished",
          "pr_url": "https://github.com/acme-corp-forks/data-pipeline/pull/19"
        }
      ],
      "d07109fcd106fa77b8180807a3bd272b": [
        {
          "session_id": "devin-d51a37d524c348589ec32f16a24c1569",
          "session_url": "https://app.devin.ai/sessions/d51a37d524c348589ec32f16a24c1569",
          "dispatched_at": "2026-01-04T15:01:00+00:00",
          "status": "error",
          "pr_url": ""
        },
        {
          "session_id": "devin-985f036257684f1f848e055e62c1f965",
          "session_url": "https://app.devin.ai/sessions/985f036257684f1f848e055e62c1f965",
          "dispatched_at": "2026-01-18T18:41:00+00:00",
          "status": "finished",
          "pr_url": "https://github.com/acme-corp-forks/api-gateway/pull/10"
        },
        {
          "session_id": "devin-ddbbac8b2dae406d880f3642c9f865c3",
          "session_url": "https://app.devin.ai/sessions/ddbbac8b2dae406d880f3642c9f865c3",
          "dispatched_at": "2025-12-03T18:23:00+00:00",
          "status": "finished",
          "pr_url": ""
        },
        {
          "session_id": "devin-6269a76472584e189eea8ff4ae53bd16",
          "session_url": "https://app.devin.ai/sessions/6269a76472584e189eea8ff4ae53bd16",
          "dispatched_at": "2026-01-24T13:55:00+00:00",
          "status": "finished",
          "pr_url": "https://github.com/acme-corp-forks/data-pipeline/pull/20"
        }
      ],
      "744f15e2e18c301e57b7e8eca35a22d5": [
        {
          "session_id": "devin-a69f4f816c054deeb3e911e3935d09fe",
          "session_url": "https://app.devin.ai/sessions/a69f4f816c054deeb3e911e3935d09fe",
          "dispatched_at": "2026-01-09T07:37:00+00:00",
          "status": "finished",
          "pr_url": ""
        },
        {
          "session_id": "devin-d4d84debc820498faa0c4f6cae19eb0a",
          "session_url": "https://app.devin.ai/sessions/d4d84debc820498faa0c4f6cae19eb0a",
          "dispatched_at": "2026-01-23T06:48:00+00:00",
          "status": "finished",
          "pr_url": "https://github.com/acme-corp-forks/mobile-backend/pull/14"
        }
      ],
      "db5236caf30a1af9115983762be5066d": [
        {
          "session_id": "devin-9df39e5c3ec545369df27a5af9d282ac",
          "session_url": "https://app.devin.ai/sessions/9df39e5c3ec545369df27a5af9d282ac",
          "dispatched_at": "2026-01-11T09:45:00+00:00",
          "status": "finished",
          "pr_url": "https://github.com/acme-corp-forks/web-platform/pull/4"
        },
        {
          "session_id": "devin-65434266c39049d7bf73962b20b73a6a",
          "session_url": "https://app.devin.ai/sessions/65434266c39049d7bf73962b20b73a6a",
          "dispatched_at": "2026-01-23T07:49:00+00:00",
          "status": "finished",
          "pr_url": "https://github.com/acme-corp-forks/mobile-backend/pull/15"
        }
      ],
      "0d662222f61a0086be839d342ebf7414": [
        {
          "session_id": "devin-893593661f6e42d388d9fe473574bf55",
          "session_url": "https://app.devin.ai/sessions/893593661f6e42d388d9fe473574bf55",
          "dispatched_at": "2026-01-23T17:34:00+00:00",
          "status": "finished",
          "pr_url": "https://github.com/acme-corp-forks/web-platform/pull/5"
        },
        {
          "session_id": "devin-5973e9c2b1954cf5ab8caefb50109de5",
          "session_url": "https://app.devin.ai/sessions/5973e9c2b1954cf5ab8caefb50109de5",
          "dispatched_at": "2026-01-25T07:36:00+00:00",
          "status": "error",
          "pr_url": ""
        }
      ],
      "6c160380c4087cf54f66841e458a0f3d": [
        {
          "session_id": "devin-378f2ee83d114aee9ed42d60938e1a92",
          "session_url": "https://app.devin.ai/sessions/378f2ee83d114aee9ed42d60938e1a92",
          "dispatched_at": "2025-11-10T14:13:00+00:00",
          "status": "stopped",
          "pr_url": ""
        }
      ],
      "727c2aee7bc5a84b00ad5b0bdb494777": [
        {
          "session_id": "devin-378f2ee83d114aee9ed42d60938e1a92",
          "session_url": "https://app.devin.ai/sessions/378f2ee83d114aee9ed42d60938e1a92",
          "dispatched_at": "2025-11-10T14:13:00+00:00",
          "status": "stopped",
          "pr_url": ""
        }
      ],
      "67590a5107a2695bcc43064428e5ac5e": [
        {
          "session_id": "devin-378f2ee83d114aee9ed42d60938e1a92",
          "session_url": "https://app.devin.ai/sessions/378f2ee83d114aee9ed42d60938e1a92",
          "dispatched_at": "2025-11-10T14:13:00+00:00",
          "status": "stopped",
          "pr_url": ""
        }
      ],
      "76cf4ef98bf20fb5e2a92c2408b5064d": [
        {
          "session_id": "devin-378f2ee83d114aee9ed42d60938e1a92",
          "session_url": "https://app.devin.ai/sessions/378f2ee83d114aee9ed42d60938e1a92",
          "dispatched_at": "2025-11-10T14:13:00+00:00",
          "status": "stopped",
          "pr_url": ""
        }
      ],
      "f908d7b7f98dddfd46ce75c648099b9e": [
        {
          "session_id": "devin-e16017965e8b4462b182d9cc74877071",
          "session_url": "https://app.devin.ai/sessions/e16017965e8b4462b182d9cc74877071",
          "dispatched_at": "2025-11-21T13:53:00+00:00",
          "status": "finished",
          "pr_url": "https://github.com/acme-corp-forks/api-gateway/pull/7"
        },
        {
          "session_id": "devin-e535bbf37fd041ab8f37f662724104eb",
          "session_url": "https://app.devin.ai/sessions/e535bbf37fd041ab8f37f662724104eb",
          "dispatched_at": "2025-11-18T07:17:00+00:00",
          "status": "finished",
          "pr_url": ""
        },
        {
          "session_id": "devin-99baaaf538eb415aa867279ef2e8d6ff",
          "session_url": "https://app.devin.ai/sessions/99baaaf538eb415aa867279ef2e8d6ff",
          "dispatched_at": "2025-12-02T08:50:00+00:00",
          "status": "finished",
          "pr_url": ""
        }
      ],
      "2f84f462dbd4fb9dadecd50a95c92f42": [
        {
          "session_id": "devin-e16017965e8b4462b182d9cc74877071",
          "session_url": "https://app.devin.ai/sessions/e16017965e8b4462b182d9cc74877071",
          "dispatched_at": "2025-11-21T13:53:00+00:00",
          "status": "finished",
          "pr_url": "https://github.com/acme-corp-forks/api-gateway/pull/7"
        },
        {
          "session_id": "devin-e535bbf37fd041ab8f37f662724104eb",
          "session_url": "https://app.devin.ai/sessions/e535bbf37fd041ab8f37f662724104eb",
          "dispatched_at": "2025-11-18T07:17:00+00:00",
          "status": "finished",
          "pr_url": ""
        },
        {
          "session_id": "devin-99baaaf538eb415aa867279ef2e8d6ff",
          "session_url": "https://app.devin.ai/sessions/99baaaf538eb415aa867279ef2e8d6ff",
          "dispatched_at": "2025-12-02T08:50:00+00:00",
          "status": "finished",
          "pr_url": ""
        }
      ],
      "a6a195bcc06ef1dfd4f08426d8ed033f": [
        {
          "session_id": "devin-10952715826b44e582cb76ecb0990fe9",
          "session_url": "https://app.devin.ai/sessions/10952715826b44e582cb76ecb0990fe9",
          "dispatched_at": "2025-12-02T11:18:00+00:00",
          "status": "finished",
          "pr_url": "https://github.com/acme-corp-forks/api-gateway/pull/8"
        },
        {
          "session_id": "devin-6e86ecc7e8014f659f08db54bb94ee07",
          "session_url": "https://app.devin.ai/sessions/6e86ecc7e8014f659f08db54bb94ee07",
          "dispatched_at": "2025-11-04T09:12:00+00:00",
          "status": "finished",
          "pr_url": "https://github.com/acme-corp-forks/mobile-backend/pull/13"
        },
        {
          "session_id": "devin-2a5d7de9b25d44b4b3846566a4403734",
          "session_url": "https://app.devin.ai/sessions/2a5d7de9b25d44b4b3846566a4403734",
          "dispatched_at": "2025-11-25T15:32:00+00:00",
          "status": "error",
          "pr_url": ""
        },
        {
          "session_id": "devin-c8c1891ba21841dcb67297e495ec4869",
          "session_url": "https://app.devin.ai/sessions/c8c1891ba21841dcb67297e495ec4869",
          "dispatched_at": "2026-01-10T09:37:00+00:00",
          "status": "finished",
          "pr_url": "https://github.com/acme-corp-forks/internal-tools/pull/23"
        }
      ],
      "b569576a8591911ea3fa341ec64b15c3": [
        {
          "session_id": "devin-985f036257684f1f848e055e62c1f965",
          "session_url": "https://app.devin.ai/sessions/985f036257684f1f848e055e62c1f965",
          "dispatched_at": "2026-01-18T18:41:00+00:00",
          "status": "finished",
          "pr_url": "https://github.com/acme-corp-forks/api-gateway/pull/10"
        },
        {
          "session_id": "devin-ddbbac8b2dae406d880f3642c9f865c3",
          "session_url": "https://app.devin.ai/sessions/ddbbac8b2dae406d880f3642c9f865c3",
          "dispatched_at": "2025-12-03T18:23:00+00:00",
          "status": "finished",
          "pr_url": ""
        },
        {
          "session_id": "devin-6269a76472584e189eea8ff4ae53bd16",
          "session_url": "https://app.devin.ai/sessions/6269a76472584e189eea8ff4ae53bd16",
          "dispatched_at": "2026-01-24T13:55:00+00:00",
          "status": "finished",
          "pr_url": "https://github.com/acme-corp-forks/data-pipeline/pull/20"
        }
      ],
      "bea71112079f26e74f84817b2d9581c9": [
        {
          "session_id": "devin-7884b76197264bfa95990f4edcb553f8",
          "session_url": "https://app.devin.ai/sessions/7884b76197264bfa95990f4edcb553f8",
          "dispatched_at": "2025-11-28T13:44:00+00:00",
          "status": "finished",
          "pr_url": ""
        },
        {
          "session_id": "devin-48337ca2d1e44f1db3f04d6898d7ebd7",
          "session_url": "https://app.devin.ai/sessions/48337ca2d1e44f1db3f04d6898d7ebd7",
          "dispatched_at": "2025-12-24T11:59:00+00:00",
          "status": "finished",
          "pr_url": "https://github.com/acme-corp-forks/data-pipeline/pull/18"
        }
      ],
      "7c41215d2e38cbe1c920df6505c3f564": [
        {
          "session_id": "devin-7884b76197264bfa95990f4edcb553f8",
          "session_url": "https://app.devin.ai/sessions/7884b76197264bfa95990f4edcb553f8",
          "dispatched_at": "2025-11-28T13:44:00+00:00",
          "status": "finished",
          "pr_url": ""
        }
      ],
      "158a0c90c54b3dc46b0ba464ed39d592": [
        {
          "session_id": "devin-b178e79f6b9046f7a7d6699484db963e",
          "session_url": "https://app.devin.ai/sessions/b178e79f6b9046f7a7d6699484db963e",
          "dispatched_at": "2025-12-01T08:30:00+00:00",
          "status": "finished",
          "pr_url": ""
        }
      ],
      "5f7cd3d20b5f0f4df9d52e651d59c65a": [
        {
          "session_id": "devin-b178e79f6b9046f7a7d6699484db963e",
          "session_url": "https://app.devin.ai/sessions/b178e79f6b9046f7a7d6699484db963e",
          "dispatched_at": "2025-12-01T08:30:00+00:00",
          "status": "finished",
          "pr_url": ""
        }
      ],
      "4ac0b1013a94956b6db8e8a814272ce4": [
        {
          "session_id": "devin-d4d84debc820498faa0c4f6cae19eb0a",
          "session_url": "https://app.devin.ai/sessions/d4d84debc820498faa0c4f6cae19eb0a",
          "dispatched_at": "2026-01-23T06:48:00+00:00",
          "status": "finished",
          "pr_url": "https://github.com/acme-corp-forks/mobile-backend/pull/14"
        }
      ],
      "26f938b74ff2785e1324daa4de64ed17": [
        {
          "session_id": "devin-5973e9c2b1954cf5ab8caefb50109de5",
          "session_url": "https://app.devin.ai/sessions/5973e9c2b1954cf5ab8caefb50109de5",
          "dispatched_at": "2026-01-25T07:36:00+00:00",
          "status": "error",
          "pr_url": ""
        }
      ],
      "835836e79e5de413772a2509a0a0b87c": [
        {
          "session_id": "devin-2a5d7de9b25d44b4b3846566a4403734",
          "session_url": "https://app.devin.ai/sessions/2a5d7de9b25d44b4b3846566a4403734",
          "dispatched_at": "2025-11-25T15:32:00+00:00",
          "status": "error",
          "pr_url": ""
        }
      ],
      "3e54c7e59f3a59406053c0be4a84a35b": [
        {
          "session_id": "devin-1acf0fa3b8264dab8dcb8e4aba52325b",
          "session_url": "https://app.devin.ai/sessions/1acf0fa3b8264dab8dcb8e4aba52325b",
          "dispatched_at": "2025-12-02T08:50:00+00:00",
          "status": "finished",
          "pr_url": "https://github.com/acme-corp-forks/internal-tools/pull/22"
        }
      ],
      "aa44bc12cb6eecde04e320c338e6b724": [
        {
          "session_id": "devin-1acf0fa3b8264dab8dcb8e4aba52325b",
          "session_url": "https://app.devin.ai/sessions/1acf0fa3b8264dab8dcb8e4aba52325b",
          "dispatched_at": "2025-12-02T08:50:00+00:00",
          "status": "finished",
          "pr_url": "https://github.com/acme-corp-forks/internal-tools/pull/22"
        }
      ],
      "bc0900121b031297450342d718ca8e8b": [
        {
          "session_id": "devin-1acf0fa3b8264dab8dcb8e4aba52325b",
          "session_url": "https://app.devin.ai/sessions/1acf0fa3b8264dab8dcb8e4aba52325b",
          "dispatched_at": "2025-12-02T08:50:00+00:00",
          "status": "finished",
          "pr_url": "https://github.com/acme-corp-forks/internal-tools/pull/22"
        }
      ]
    },
    "objective_progress": [],
    "scan_schedule": {
      "https://github.com/acme-corp/web-platform": {
        "last_scan": "2026-01-24T07:36:00+00:00",
        "next_scan": "2026-01-31T07:36:00+00:00",
        "schedule": "weekly"
      },
      "https://github.com/acme-corp/api-gateway": {
        "last_scan": "2026-01-25T07:36:00+00:00",
        "next_scan": "2026-02-01T07:36:00+00:00",
        "schedule": "weekly"
      },
      "https://github.com/acme-corp/mobile-backend": {
        "last_scan": "2026-01-21T07:36:00+00:00",
        "next_scan": "2026-01-28T07:36:00+00:00",
        "schedule": "weekly"
      },
      "https://github.com/acme-corp/data-pipeline": {
        "last_scan": "2026-01-22T07:36:00+00:00",
        "next_scan": "2026-01-29T07:36:00+00:00",
        "schedule": "weekly"
      },
      "https://github.com/acme-corp/internal-tools": {
        "last_scan": "2026-01-22T07:36:00+00:00",
        "next_scan": "2026-01-29T07:36:00+00:00",
        "schedule": "weekly"
      }
    }
  }
};
