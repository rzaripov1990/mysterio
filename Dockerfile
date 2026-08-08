FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod tidy
COPY . .
RUN CGO_ENABLED=0 go build -buildvcs=false -o /out/mysterio .

FROM alpine:3.20
# ca-certificates from build image (apk often blocked by corporate TLS MITM)
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/mysterio /usr/local/bin/mysterio
# Default rules shipped in the image; override by mounting a file at this
# path (see docker-compose.yml) or setting RULES_PATH to a different path.
COPY configs/rules.yaml /etc/mysterio/rules.yaml
ENV PORT=:8080
ENV RULES_PATH=/etc/mysterio/rules.yaml
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/mysterio"]
