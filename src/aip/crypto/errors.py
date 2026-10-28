"""Exceptions raised for inputs the cryptographic primitives refuse to process."""


class CryptoInputError(ValueError):
    """Base class: an input to a canonicalization or hashing function is not allowed."""


class CanonicalizationError(CryptoInputError):
    """A value cannot be represented in canonical JSON."""


class TimestampError(CryptoInputError):
    """A timestamp is not valid RFC 3339, or not in canonical form where that is required."""


class LeafError(CryptoInputError):
    """A payload, typed path, leaf or leaf set is malformed."""


class HashInputError(CryptoInputError):
    """An input to a content or record hash is malformed."""
