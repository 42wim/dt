FROM docker.io/library/golang AS builder
RUN CGO_ENABLED=0 go install -a -ldflags '-extldflags "-static"'  github.com/42wim/dt@master

FROM scratch
COPY --from=0 /go/bin/dt /dt
ENTRYPOINT ["/dt"]
