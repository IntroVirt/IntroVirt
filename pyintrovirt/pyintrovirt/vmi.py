from typing import Union
from contextlib import ContextDecorator

import introvirt


class VMIDomain(ContextDecorator):

    def __init__(self, target: Union[int, str]):
        """
        Initialize a VMIDomain object and attach to the target domain.

        Args:
            target: The target domain to attach to. Can be an integer domain ID or a string domain name.
        """
        self.target = target
        self.hypervisor = introvirt.Hypervisor.instance()
        self.domain = self.hypervisor.attach_domain(target)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def close(self) -> None:
        """Detach from the domain. Safe to call multiple times."""
        if self.domain is not None:
            self.domain.interrupt()
            self.domain = None