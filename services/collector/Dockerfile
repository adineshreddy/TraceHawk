FROM golang:1.26.0-bookworm@sha256:2a0ba12e116687098780d3ce700f9ce3cb340783779646aafbabed748fa6677c AS build
WORKDIR /src
COPY services/collector/go.mod services/collector/go.sum ./
RUN go mod download
COPY services/collector/*.go ./
RUN mkdir /state
RUN CGO_ENABLED=0 go build -trimpath -o /collector .
FROM scratch
COPY --from=build /collector /collector
COPY --chown=10001:10001 --from=build /state /state
COPY contracts/schemas /app/contracts/schemas
COPY scenarios/phase0 /app/scenarios/phase0
COPY scenarios/phase1-benign /app/scenarios/phase1-benign
USER 10001
ENTRYPOINT ["/collector"]
