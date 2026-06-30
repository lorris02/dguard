import atexit
import os
import signal
import sys

from agent.config import PROXY_PORT
from agent.installer import install_certificate, set_system_proxy, unset_system_proxy


ADDON_PATH = os.path.join(os.path.dirname(__file__), "interceptor.py")


def _shutdown():
    print("\nDGuard agent stopping — restoring system proxy settings...")
    unset_system_proxy()


def main():
    if "--install-cert" in sys.argv:
        install_certificate()
        return

    atexit.register(_shutdown)
    signal.signal(signal.SIGINT, lambda s, f: sys.exit(0))
    signal.signal(signal.SIGTERM, lambda s, f: sys.exit(0))

    set_system_proxy(PROXY_PORT)
    print(f"DGuard agent running on port {PROXY_PORT}")
    print("All AI-bound traffic is now being scanned.")
    print("Press Ctrl+C to stop.\n")

    # Import here so mitmproxy logging doesn't fire before our banner
    from mitmproxy.tools.main import mitmdump
    mitmdump(["-p", str(PROXY_PORT), "-s", ADDON_PATH, "--quiet"])


if __name__ == "__main__":
    main()
