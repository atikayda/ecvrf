.PHONY: test test-python test-go test-rust test-ts test-c test-csharp test-kotlin test-haskell test-zig test-swift test-solidity test-solana test-cross vectors clean cli

PYTHON := $(if $(wildcard python/.venv/bin/python3),$(CURDIR)/python/.venv/bin/python3,python3)

test: test-python test-go test-rust test-ts test-c test-csharp test-kotlin test-haskell test-zig test-swift test-solidity test-solana test-cross

cli:
	mkdir -p scripts/.bin
	cd go && go build -o ../scripts/.bin/ecvrf-go ./cmd/ecvrf-cli
	cd rust && cargo build --example cli --release
	cd typescript && npm run build

test-python:
	cd python && $(PYTHON) ecvrf.py

test-go:
	cd go && go test ./...

test-rust:
	cd rust && cargo test

test-ts:
	cd typescript && npm test

test-c:
	cd c && make test

test-csharp:
	cd csharp && dotnet test

test-kotlin:
	cd kotlin && ./gradlew test

test-haskell:
	cd haskell && cabal build all && cabal run ecvrf-test

test-zig:
	cd zig && zig build test

test-swift:
	cd swift && swift build && swift run ecvrf-test

test-solidity:
	cd solidity && forge test

test-solana:
	cd solana && cargo test

test-cross:
	bash scripts/cross-validate.sh

vectors:
	cd python && $(PYTHON) generate.py

clean:
	cd go && go clean
	cd rust && cargo clean
	rm -rf typescript/dist
	rm -rf scripts/.bin
	cd c && make clean
	rm -rf csharp/Ecvrf/bin csharp/Ecvrf/obj csharp/Ecvrf.Tests/bin csharp/Ecvrf.Tests/obj
	cd kotlin && ./gradlew clean
	rm -rf haskell/dist-newstyle
	rm -rf zig/.zig-cache zig/zig-out
	rm -rf swift/.build
	rm -rf solidity/out solidity/cache
	cd solana && cargo clean
