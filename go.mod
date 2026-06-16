module github.com/reclaimprotocol/reclaim-tee

go 1.26

require (
	cloud.google.com/go/firestore v1.22.0
	cloud.google.com/go/kms v1.29.0
	cloud.google.com/go/logging v1.16.0
	cloud.google.com/go/secretmanager v1.19.0
	filippo.io/nistec v0.0.4
	github.com/KGKallasmaa/countries v0.2.0
	github.com/consensys/gnark v0.14.0
	github.com/coreos/go-json v0.0.0-20231102161613-e49c8866685a
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.1
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/google/uuid v1.6.0
	github.com/gorilla/websocket v1.5.3
	github.com/joho/godotenv v1.5.1
	github.com/markkurossi/mpc v0.0.0-20260616034910-9c484ce016a7
	github.com/mr-tron/base58 v1.3.0
	github.com/reclaimprotocol/jsonpathplus-go/v2 v2.0.1
	github.com/reclaimprotocol/xpath-go v1.4.1
	github.com/reclaimprotocol/zk-symmetric-crypto/gnark v0.0.0-20260407154851-d134fefd8eff
	github.com/xeipuuv/gojsonschema v1.2.0
	go.mozilla.org/pkcs7 v0.9.0
	go.uber.org/zap v1.27.1
	golang.org/x/crypto v0.50.0
	golang.org/x/sync v0.20.0
	golang.org/x/time v0.15.0
	google.golang.org/api v0.276.0
	google.golang.org/grpc v1.80.0
	google.golang.org/protobuf v1.36.11
)

require (
	cloud.google.com/go v0.123.0 // indirect
	cloud.google.com/go/auth v0.20.0 // indirect
	cloud.google.com/go/auth/oauth2adapt v0.2.8 // indirect
	cloud.google.com/go/compute/metadata v0.9.0 // indirect
	cloud.google.com/go/iam v1.9.0 // indirect
	cloud.google.com/go/longrunning v0.11.0 // indirect
	github.com/bits-and-blooms/bitset v1.24.4 // indirect
	github.com/blang/semver/v4 v4.0.0 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/consensys/gnark-crypto v0.20.1 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/fxamacker/cbor/v2 v2.9.1 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/google/pprof v0.0.0-20260402051712-545e8a4df936 // indirect
	github.com/google/s2a-go v0.1.9 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.3.15 // indirect
	github.com/googleapis/gax-go/v2 v2.22.0 // indirect
	github.com/ingonyama-zk/icicle-gnark/v3 v3.2.2 // indirect
	github.com/markkurossi/crypto v0.0.0-20240520115340-daed3f9a1082 // indirect
	github.com/markkurossi/tabulate v0.0.0-20251126123558-a08056f6160f // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.21 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/ronanh/intcomp v1.1.1 // indirect
	github.com/rs/zerolog v1.35.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/xeipuuv/gojsonpointer v0.0.0-20190905194746-02993c407bfb // indirect
	github.com/xeipuuv/gojsonreference v0.0.0-20180127040603-bd5ef7bd5415 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.68.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.68.0 // indirect
	go.opentelemetry.io/otel v1.43.0 // indirect
	go.opentelemetry.io/otel/metric v1.43.0 // indirect
	go.opentelemetry.io/otel/trace v1.43.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/exp v0.0.0-20260410095643-746e56fc9e2f // indirect
	golang.org/x/net v0.53.0 // indirect
	golang.org/x/oauth2 v0.36.0 // indirect
	golang.org/x/sys v0.43.0 // indirect
	golang.org/x/text v0.36.0 // indirect
	google.golang.org/genproto v0.0.0-20260414002931-afd174a4e478 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20260414002931-afd174a4e478 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260414002931-afd174a4e478 // indirect
)

replace (
	github.com/consensys/gnark-crypto v0.20.1 => github.com/consensys/gnark-crypto v0.19.2
	github.com/reclaimprotocol/zk-symmetric-crypto/gnark v0.0.0-20260407154851-d134fefd8eff => github.com/reclaimprotocol/zk-symmetric-crypto/gnark v0.0.0-20251205140100-6fd752973b8f
)
