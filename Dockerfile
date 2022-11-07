FROM busybox:latest
COPY tagger /usr/bin/tagger
ENTRYPOINT ["/usr/bin/tagger"]
CMD ["--config", "/etc/tagger/tagger.yml"]
