from http.server import HTTPServer, BaseHTTPRequestHandler


class MimicHandler(BaseHTTPRequestHandler):
    # Match the response signature in the example
    server_version = "SimpleHTTP/0.6"
    sys_version = "Python/3.10.11"
    protocol_version = "HTTP/1.0"

    EXPECTED_PATH = "/good"
    EXPECTED_USER_AGENT = (
        "Mozilla/5.0 (Avocado OS; 1-Core Toaster) AppleWebKit/537.36 (XML, like Gecko) FLARE/1.0"
    )
    EXPECTED_AUTHORIZATION = (
        "Bearer e4b8058f06f7061e8f0f8ed15d23865ba2427b23a695d9b27bc308a26d"
    )

    RESPONSE_JSON = (
        "{" +
        "\"d\": \"085d8ea282da6cf76bb2765bc3b26549a1f6bdf08d8da2a62e05ad96ea645c685da48d66ed505e2e28b968d15dabed15ab1500901eb9da4606468650f72550483f1e8c58ca13136bb8028f976bedd36757f705ea5f74ace7bd8af941746b961c45bcac1eaf589773cecf6f1c620e0e37ac1dfc9611aa8ae6e6714bb79a186f47896f18203eddce97f496b71a630779b136d7bf0c82d560\""
        + "}"
    ).encode("ascii")

    def do_GET(self):
        if self.path != self.EXPECTED_PATH:
            self.send_error(404)
            return

        user_agent = self.headers.get("User-Agent", "")
        authorization = self.headers.get("Authorization", "")

        if user_agent != self.EXPECTED_USER_AGENT or authorization != self.EXPECTED_AUTHORIZATION:
            self.send_error(401)
            return

        self.send_response(200, "OK")
        self.send_header("Content-type", "application/json")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(self.RESPONSE_JSON)


def run(host: str = "127.0.0.1", port: int = 8000) -> None:
    httpd = HTTPServer((host, port), MimicHandler)
    print(f"Serving on http://{host}:{port}")
    httpd.serve_forever()


if __name__ == "__main__":
    run()


