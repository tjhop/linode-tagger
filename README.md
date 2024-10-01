# Linode Tagger

[![license](https://img.shields.io/github/license/tjhop/linode-tagger)](https://github.com/tjhop/linode-tagger/blob/master/LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/tjhop/linode-tagger)](https://goreportcard.com/report/github.com/tjhop/linode-tagger)
[![golangci-lint](https://github.com/tjhop/linode-tagger/actions/workflows/golangci-lint.yaml/badge.svg)](https://github.com/tjhop/linode-tagger/actions/workflows/golangci-lint.yaml)
[![Latest Release](https://img.shields.io/github/v/release/tjhop/linode-tagger)](https://github.com/tjhop/linode-tagger/releases/latest)
[![GitHub Downloads (all assets, all releases)](https://img.shields.io/github/downloads/tjhop/linode-tagger/total)](https://github.com/tjhop/linode-tagger/releases/latest)

Tagger is an application that can enforce the presence/absence of API tags in bulk across all taggable Linode APIv4 resource objects:

| Object Type | API Token Scopes Required |
| --- | --- |
| Instances | `linodes:read_write` |
| Volumes | `volumes:read_write` |
| NodeBalancers | `nodebalancers:read_write` |
| Domains | `domains:read_write` |
| LKEClusters | `lke:read_write` |
| Firewalls | `firewall:read_write` |

## Motivation

Tools like Terraform/Pulumi that are capable of programmatically managing all aspects of API resources are great -- but if there is already a large amount of infrastructure deployed (and the infrastructure isn't suitable to directly import to something like Terraform state as-is), it can be difficult to manage tags across API resources.

API tags provide a powerful and flexible way to dynamically annotate infrastructure. With tools like [Prometheus](https://prometheus.io), you can even discover monitoring targets using [Linode Service Discovery](https://prometheus.io/docs/prometheus/latest/configuration/configuration/#linode_sd_config) based on API tags.

So it's helpful to be able to manage tags on Linode APIv4 resources en-masse -- but how can that be done in an idempotent and consistent way? This is where `tagger` comes into play. With tagger, you write a configuration file defining a list of tag rules for each of the various Linode APIv4 taggable objects (instances, domains, nodebalancers, volumes, LKE clusters, firewalls).

Each rule is a regex to be matched against the resource's human-readable label, and a list of tags that should be enforced as either `present` or `absent` on the resource. `tagger` is idempotent and doesn't update resources unless required, and can be run in `--dry-run` mode to see what changes are waiting. JSON output is provided as well with the `--json` flag for easy manipulation/inspection of the diffs and integration with other tools. Full help text:

```bash
docker run --rm ghcr.io/tjhop/linode-tagger -h
Usage of /usr/bin/tagger:
pflag: help requested
      --config string          Path to configuration file to use
      --dry-run                Don't apply the tag changes
      --json                   Provide changes in JSON
      --logging.level string   Logging level may be one of: [debug, info, warn, error]
  -v, --version                Print version information about this build of tagger
```

## Usage

### Configuration


Provide a Linode APIv4 token with appropriate scope(s) to tag your desired objects as an environment variable.


```bash
LINODE_TOKEN="${your_api_token}" tagger --config /etc/tagger/tagger.yml
```

### Docker Usage

Provide a Linode APIv4 token with appropriate scope(s) to tag your desired objects as an environment variable, along with a bind mount volume for the linode-tagger configuration.

```
docker run \
-e LINODE_TOKEN="<linode-api-v4-token>" \
-v /path/to/tagger.yml:/etc/tagger/tagger.yml \
ghcr.io/tjhop/linode-tagger
```

## Building

This project uses [goreleaser](https://goreleaser.com/) to manage builds.
To manually make a build, you can do:

```bash
goreleaser build --rm-dist --single-target --snapshot
```

## Contributions
Commits *must* follow [Conventional Commit format](https://www.conventionalcommits.org/en/v1.0.0/). This repository uses [GoReleaser](https://goreleaser.com/) and semver git tags that are determined by the type of commit.

## Making a Release
1. Create and merge pull request to `linode-tagger` like normal
2. Cut tag for release to trigger goreleaser build via Github Actions

    Note: It's highly recommended to install [SVU](https://github.com/caarlos0/svu) to help with tag creation.

    ```bash
    # origin   == your fork
    # upstream == github.com/tjhop/linode-tagger
    git checkout main
    git pull --tags upstream main
    git tag $(svu next)
    git push --tags upstream main
    ```
