from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from soc.api.product import ProductApi


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the mini LLM SOC product API.")
    parser.add_argument("--config", default="config/settings.example.yaml")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    api = ProductApi(args.config)
    handler = _handler_for(api)
    server = ThreadingHTTPServer((args.host, args.port), handler)
    print(f"serving mini LLM SOC product API on http://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        return 0
    finally:
        server.server_close()
    return 0


def _handler_for(api: ProductApi):
    class ProductApiHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self._handle()

        def do_POST(self) -> None:
            self._handle()

        def do_OPTIONS(self) -> None:
            self.send_response(204)
            self._send_common_headers()
            self.end_headers()

        def _handle(self) -> None:
            if self.command == "GET" and self._serve_static_asset():
                return
            body = self.rfile.read(_content_length(self.headers)) if self.command == "POST" else b""
            response = api.handle(self.command, self.path, body)
            encoded = json.dumps(response.body, ensure_ascii=False, indent=2).encode("utf-8")
            self.send_response(response.status)
            self._send_common_headers()
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def _send_common_headers(self) -> None:
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")

        def log_message(self, format: str, *args: Any) -> None:
            return

        def _serve_static_asset(self) -> bool:
            request_path = unquote(self.path.split("?", 1)[0])
            static_root = Path(__file__).resolve().parents[1] / "gui" / "static"
            if request_path in ("", "/"):
                asset_path = static_root / "index.html"
            elif request_path.startswith("/static/"):
                asset_path = static_root / request_path.removeprefix("/static/")
            else:
                return False

            try:
                resolved = asset_path.resolve()
                resolved.relative_to(static_root.resolve())
            except ValueError:
                self.send_error(404)
                return True

            if not resolved.is_file():
                self.send_error(404)
                return True

            content = resolved.read_bytes()
            self.send_response(200)
            self._send_common_headers()
            self.send_header("Content-Type", _content_type(resolved))
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
            return True

    return ProductApiHandler


def _content_length(headers) -> int:
    try:
        return int(headers.get("Content-Length") or 0)
    except ValueError:
        return 0


def _content_type(path: Path) -> str:
    if path.suffix == ".html":
        return "text/html; charset=utf-8"
    if path.suffix == ".css":
        return "text/css; charset=utf-8"
    if path.suffix == ".js":
        return "text/javascript; charset=utf-8"
    return "application/octet-stream"


if __name__ == "__main__":
    raise SystemExit(main())
