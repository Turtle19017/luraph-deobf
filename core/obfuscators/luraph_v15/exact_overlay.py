"""Select ID-free scalar literals at explicitly allow-listed exact paths.

This helper does not load snapshots, merge caches, or perform live decoding.
"""
import math


def select_exact_scalars(candidates, overrides, current_requests):
    accepted, rejected = {}, {}
    for path in candidates:
        if path not in current_requests or path not in overrides:
            rejected[path] = "not_an_exact_current_request_override"
            continue
        value = overrides[path]
        if type(value) in (bool, int):
            accepted[path] = value
        elif type(value) is float and math.isfinite(value):
            accepted[path] = value
        elif isinstance(value, dict) and set(value) == {"s"} and isinstance(value["s"], str):
            try:
                accepted[path] = bytes.fromhex(value["s"])
            except ValueError:
                rejected[path] = "invalid_encoded_string"
        else:
            rejected[path] = "non_scalar_requires_separate_identity_proof"
    return accepted, rejected
