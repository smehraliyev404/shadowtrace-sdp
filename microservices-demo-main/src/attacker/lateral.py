"""ShadowTrace lateral-movement client (runs INSIDE the attacker pod).

Simulates an adversary with an in-cluster foothold calling internal gRPC
services DIRECTLY -- bypassing the frontend that legitimately fronts them. It
hits productcatalogservice, currencyservice and cartservice on their internal
ports, services a normal external user only ever reaches THROUGH the frontend.

Why an instrumented client and not raw grpcurl: grpcurl injects no trace
context, so the target's span would be a parentless root -- no edge, invisible
to the per-edge features. With opentelemetry-instrument wrapping this process,
gRPC context propagates and each call becomes a real edge

    attacker -> productcatalogservice   (and -> currencyservice, -> cartservice)

Those edges have NO precedent in normal traffic (nothing but the frontend calls
these services), so causal_history_distance spikes -- the feature that exists
precisely to flag call paths without historical precedent. This is the research
framework's headline threat (§1, lateral movement).

Invoked via `kubectl exec` from scripts/attacks/lateral_movement.py.
"""

import time
import uuid
import argparse

import grpc
import demo_pb2
import demo_pb2_grpc

PRODUCTCATALOG = "productcatalogservice:3550"
CURRENCY = "currencyservice:7000"
CART = "cartservice:7070"


def move(duration):
    pc = demo_pb2_grpc.ProductCatalogServiceStub(grpc.insecure_channel(PRODUCTCATALOG))
    cur = demo_pb2_grpc.CurrencyServiceStub(grpc.insecure_channel(CURRENCY))
    cart = demo_pb2_grpc.CartServiceStub(grpc.insecure_channel(CART))
    fake_user = f"attacker-{uuid.uuid4().hex[:8]}"

    start, calls, errors = time.time(), 0, 0
    while time.time() - start < duration:
        for fn in (
            lambda: pc.ListProducts(demo_pb2.Empty()),
            lambda: cur.GetSupportedCurrencies(demo_pb2.Empty()),
            lambda: cart.GetCart(demo_pb2.GetCartRequest(user_id=fake_user)),
        ):
            try:
                fn()
                calls += 1
            except grpc.RpcError:
                errors += 1
        time.sleep(0.3)   # throttled: buried in normal traffic, keeps cluster healthy

    print(f"[lateral] {calls} direct internal calls in {time.time()-start:.0f}s ({errors} errors)")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--duration", type=int, required=True)
    move(p.parse_args().duration)
