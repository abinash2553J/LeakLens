"""Safe example showing how an application can load secrets at runtime."""

import os

# Store the actual value in your local environment or secret manager.
# Never replace this with a credential copied into source control.
api_key = os.getenv("EXAMPLE_API_KEY")

if not api_key:
    raise RuntimeError("Set EXAMPLE_API_KEY in the runtime environment")

print("API key configured:", bool(api_key))
