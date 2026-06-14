import os
import hvac

VAULT_ADDR = os.getenv("VAULT_ADDR", "http://127.0.0.1:8200")
VAULT_TOKEN = os.getenv("VAULT_TOKEN")

client = hvac.Client(
    url=VAULT_ADDR,
    token=VAULT_TOKEN
)

def get_secrets():
    response = client.secrets.kv.v2.read_secret_version(
        path="clamnet"
    )
    return response["data"]["data"]
