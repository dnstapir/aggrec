from http_message_signatures import algorithms

SUPPORTED_SIGNATURE_ALGORITHMS: dict[str, type] = {
    algorithm_cls.algorithm_id: algorithm_cls
    for algorithm_cls in [
        algorithms.RSA_PSS_SHA512,
        algorithms.RSA_V1_5_SHA256,
        algorithms.ED25519,
        algorithms.ECDSA_P256_SHA256,
    ]
}


def validate_signature_algorithm(alg: str) -> str:
    """Validate that the given signature algorithm is supported."""

    if alg not in SUPPORTED_SIGNATURE_ALGORITHMS:
        raise ValueError("Unsupported signature algorithm")
    return alg
