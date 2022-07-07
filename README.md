# Linode Tagger

Tagger is an application that can enforce the presence/absence of API tags in bulk across all of your Linode instances.
_Note_: currently, `tagger` only supports Linode instances.
This application may be updated in the future to support enforcing tag sets on other Linode APIv4 resource objects.

## Building

This project uses [goreleaser](https://goreleaser.com/) to manage builds.
To manually make a build, you can do:

```bash
goreleaser build --rm-dist --single-target --snapshot
```

## Usage

```bash
LINODE_TOKEN="${your_api_token}" tagger --config /etc/tagger/tagger.yml
```

## Releases
