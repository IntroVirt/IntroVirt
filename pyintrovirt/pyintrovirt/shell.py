import code
from pyintrovirt import *


def main():
    """Entry Point."""
    namespace = globals()
    namespace.update(locals())
    banner = "PyIntroVirt Interactive Shell!"
    code.interact(banner=banner, local=namespace, exitmsg="Goodbye!")


if __name__ == "__main__":
    main()