FROM alpine:latest as certs
RUN apk update && apk add ca-certificates

FROM busybox:latest
COPY --from=certs /etc/ssl/certs /etc/ssl/certs

COPY tagger /usr/bin/tagger
ENTRYPOINT ["/usr/bin/tagger"]
CMD ["--config", "/etc/tagger/tagger.yml"]
