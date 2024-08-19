FROM ubuntu:24.04 as runner

RUN apt update && apt install -y git
WORKDIR /app

FROM golang:1.23 as builder

COPY . .
RUN go build -o /build/git-scan cmd/git-scan/main.go

FROM runner
COPY --from=builder /build/git-scan /app/git-scan
ENTRYPOINT ["/app/git-scan"]