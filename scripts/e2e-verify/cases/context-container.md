# docker run --rm -v <repo>:/workspace ghcr.io/jdiegoisaza/linceo:latest context

**Status:** ok
**Exit code:** 0

```bash
docker run --rm -v '<WORKSPACE>:/workspace' ghcr.io/jdiegoisaza/linceo:latest context
```

```
Platform: local (auto-detected)

Azure Pipelines environment (checked regardless of the platform selected):
  TF_BUILD                              not set              — auto-detection sentinel
  BUILD_REPOSITORY_NAME                 not set              — repository (required)
  BUILD_SOURCEVERSION                   not set              — commit (required)
  BUILD_SOURCEBRANCH                    not set              — branch, non-PR trigger
  SYSTEM_PULLREQUEST_SOURCEBRANCH       not set              — branch, PR trigger
  SYSTEM_PULLREQUEST_PULLREQUESTID      not set              — pull request id, Azure DevOps internal
  SYSTEM_PULLREQUEST_PULLREQUESTNUMBER  not set              — pull request id, GitHub-backed repository
  BUILD_BUILDID                         not set              — build id
  BUILD_REPOSITORY_URI                  not set              — source URL
  SYSTEM_COLLECTIONURI                  not set              — organization URL (used by the azure_devops policy source)
  SYSTEM_TEAMPROJECT                    not set              — project name (used by the azure_devops policy source)

GitHub Actions environment (checked regardless of the platform selected):
  GITHUB_ACTIONS     not set              — auto-detection sentinel
  GITHUB_REPOSITORY  not set              — repository (required)
  GITHUB_SHA         not set              — commit (required)
  GITHUB_REF         not set              — branch/tag ref, non-PR trigger
  GITHUB_HEAD_REF    not set              — branch, PR trigger
  GITHUB_RUN_ID      not set              — build id
  GITHUB_SERVER_URL  not set              — source URL (combined with GITHUB_REPOSITORY)

Every variable above is unset, so `auto` selected `local`. If this process is meant to be running inside a CI platform's own runner or agent, its environment was not passed into this one — a `docker run` invocation must forward each variable explicitly with `-e VAR` (see README.md, "Container image"). If this really is a local run, this is expected and there is nothing to fix.

Resolved ExecutionContext:
  platform: local
  repository: workspace
  workspace_path: /workspace
  commit: <COMMIT>
  branch: main
  pull_request_id: (none)
  build_id: (none)
  source_url: (none)
```
