# Build the example API from the module root.
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/example ./example

FROM alpine:3.20
RUN adduser -D -H app
COPY --from=build /out/example /usr/local/bin/example
USER app
EXPOSE 8080
ENTRYPOINT ["example"]
