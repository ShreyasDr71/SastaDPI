
import sys
import os

# Allow running as "python proxy_tool/" by adding parent to path
if __package__ is None and not hasattr(sys, "frozen"):
    path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sys.path.insert(0, path)

from proxy_tool.tui import ProxyTui

if __name__ == "__main__":
    app = ProxyTui()
    app.run()
