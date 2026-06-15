#!/bin/bash

echo "=== TEE + MPC Protocol - Demo Script ==="
echo ""
echo "Starts router (standalone), TEE_K, TEE_T locally, then runs the demo"
echo "client through the router: /allocate -> connect to the allocated pair"
echo "with the JWT it returned."
echo ""

# Build all services first
echo "Building services..."
./build.sh
if [ $? -ne 0 ]; then
    echo "Build failed"
    exit 1
fi
echo "All services built successfully"
echo ""

ROUTER_PORT=9090
ROUTER_URL=http://localhost:${ROUTER_PORT}
TEEK_PORT=8080
TEET_PORT=8081
JWT_ISSUER=router.reclaimprotocol.org

cleanup() {
    echo ""
    echo "Shutting down services..."
    for pid_var in ROUTER_PID TEEK_PID TEET_PID; do
        pid=${!pid_var:-}
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null
            wait "$pid" 2>/dev/null
        fi
    done
    echo "Demo completed"
}
trap cleanup SIGINT SIGTERM

# 1. Router in standalone mode (in-memory store, in-process signer, no auth).
echo "Starting router on port ${ROUTER_PORT}..."
ROUTER_STANDALONE=true \
JWT_ISSUER=${JWT_ISSUER} \
PORT=${ROUTER_PORT} \
./bin/router > /tmp/demo_router.log 2>&1 &
ROUTER_PID=$!

# Wait for router /healthz.
for i in {1..20}; do
    if curl -sf "${ROUTER_URL}/healthz" >/dev/null 2>&1; then
        break
    fi
    if ! kill -0 $ROUTER_PID 2>/dev/null; then
        echo "Router failed to start. Log:"
        cat /tmp/demo_router.log
        exit 1
    fi
    sleep 0.2
done

# 2. Fetch the router's signing pubkey so TEEs can verify allocation JWTs.
JWT_PUBKEY=$(curl -sf "${ROUTER_URL}/jwt-pubkey")
if [ -z "$JWT_PUBKEY" ]; then
    echo "Failed to fetch /jwt-pubkey from router"
    cat /tmp/demo_router.log
    cleanup
    exit 1
fi
echo "Router ready, pubkey fetched."
echo ""

# 3. TEE_K in router mode. No launcher socket -> local-dev path (plain HTTP,
#    no RA-TLS, no peer mTLS, sentinel image_digest at /register).
echo "Starting TEE_K on port ${TEEK_PORT}..."
ROUTER_URL=${ROUTER_URL} \
SELF_ADDR=127.0.0.1:${TEEK_PORT} \
PEER_ADDR=127.0.0.1:${TEET_PORT} \
JWT_PUBLIC_KEY="${JWT_PUBKEY}" \
EXPECTED_JWT_ISSUER=${JWT_ISSUER} \
PORT=${TEEK_PORT} \
./bin/tee_k > /tmp/demo_teek.log 2>&1 &
TEEK_PID=$!

# 4. TEE_T same shape.
echo "Starting TEE_T on port ${TEET_PORT}..."
ROUTER_URL=${ROUTER_URL} \
SELF_ADDR=127.0.0.1:${TEET_PORT} \
PEER_ADDR=127.0.0.1:${TEEK_PORT} \
JWT_PUBLIC_KEY="${JWT_PUBKEY}" \
EXPECTED_JWT_ISSUER=${JWT_ISSUER} \
PORT=${TEET_PORT} \
./bin/tee_t > /tmp/demo_teet.log 2>&1 &
TEET_PID=$!

# 5. Wait for the pair to reach "ready" status — /allocate succeeds only
#    after both TEEs register, exchange pair_id, and finish OT precompute.
echo "Waiting for TEEs to register and complete OT precompute..."
PAIR_READY=0
for i in {1..50}; do
    if ! kill -0 $TEEK_PID 2>/dev/null; then
        echo "TEE_K died during startup. Log:"
        cat /tmp/demo_teek.log
        cleanup
        exit 1
    fi
    if ! kill -0 $TEET_PID 2>/dev/null; then
        echo "TEE_T died during startup. Log:"
        cat /tmp/demo_teet.log
        cleanup
        exit 1
    fi
    if curl -sf -X POST "${ROUTER_URL}/allocate" \
        -H "Content-Type: application/json" \
        -d '{"client_nonce":"probe"}' >/dev/null 2>&1; then
        PAIR_READY=1
        echo "Pair ready."
        break
    fi
    sleep 0.5
done
if [ $PAIR_READY -ne 1 ]; then
    echo "TEE pair never reached ready state. Logs:"
    echo "--- TEE_K ---"
    cat /tmp/demo_teek.log
    echo "--- TEE_T ---"
    cat /tmp/demo_teet.log
    cleanup
    exit 1
fi
echo ""

# 6. Run the client through the router.
echo "Running demo client through router..."
echo ""
./bin/client --router-url=${ROUTER_URL} "$@"
CLIENT_EXIT_CODE=$?

echo ""
echo "Client finished with exit code: $CLIENT_EXIT_CODE"

if [ $CLIENT_EXIT_CODE -ne 0 ]; then
    echo ""
    echo "Service logs for debugging:"
    echo "--- router ---"
    cat /tmp/demo_router.log
    echo ""
    echo "--- TEE_K ---"
    cat /tmp/demo_teek.log
    echo ""
    echo "--- TEE_T ---"
    cat /tmp/demo_teet.log
fi

cleanup
rm -f /tmp/demo_*.log
exit $CLIENT_EXIT_CODE
