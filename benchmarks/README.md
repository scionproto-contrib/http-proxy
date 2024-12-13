# Analysis

## Test coverage

```bash
go test ./... -count=1 -coverpkg=./... -coverprofile=test.cov
go tool cover -func test.cov
go tool cover -html=test.cov
```

## Benchmark

```bash
go test -bench=. -count=6 -run=^$ github.com/scionproto-contrib/http-proxy/forward > bench_forward.txt
benchstat bench_forward.txt
```