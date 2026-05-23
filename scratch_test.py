from soc.api.product import ProductApi
import json

def test():
    api = ProductApi()
    payload = {"tier1_provider":"ollama","tier1_model":"gemma4:e4b","threshold_low":0.3,"threshold_high":0.95}
    res = api._admin_config(payload)
    print("status:", res.status)
    print("body:", res.body)

if __name__ == "__main__":
    test()
