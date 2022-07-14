FROM golang:1.18-alpine
COPY tagger /usr/bin/tagger
ENTRYPOINT ["/usr/bin/tagger"]
CMD ["--config", "/etc/tagger/tagger.yml"]
