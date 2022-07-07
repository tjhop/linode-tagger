# Linode Tagger

Tagger is an application that can enforce the presence/absence of API tags in bulk across all of your Linode instances.
_Note_: currently, `tagger` only supports Linode instances.
This application may be updated in the future to support enforcing tag sets on other Linode APIv4 resource objects.

## Usage

```bash
LINODE_TOKEN="${your_api_token}" tagger --config /etc/tagger/tagger.yml
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
