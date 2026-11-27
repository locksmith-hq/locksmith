"""Holder for a credential string: no value in repr or str, refuses pickle and copy."""

from __future__ import annotations

from typing import NoReturn


class Secret:
    __slots__ = ("_v",)

    def __init__(self, value: str) -> None:
        object.__setattr__(self, "_v", value)

    def reveal(self) -> str:
        """The value, for the one place that puts it on the wire."""
        return self._v

    def __repr__(self) -> str:
        return "Secret(<redacted>)"

    __str__ = __repr__

    def __format__(self, spec: str) -> str:
        return "<redacted>"

    def __setattr__(self, name: str, value: object) -> NoReturn:
        raise AttributeError("Secret is immutable")

    def __reduce__(self) -> NoReturn:
        raise TypeError("Secret cannot be pickled")

    def __reduce_ex__(self, protocol: int) -> NoReturn:
        raise TypeError("Secret cannot be pickled")

    def __copy__(self) -> NoReturn:
        raise TypeError("Secret cannot be copied")

    def __deepcopy__(self, memo: object) -> NoReturn:
        raise TypeError("Secret cannot be copied")

    def __eq__(self, other: object) -> bool:
        return self is other

    def __hash__(self) -> int:
        return id(self)
