from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import os
import threading

# Global variables to track state across requests
response_index = 0
responses = []
lock = threading.Lock()


class LocalMimicHandler(BaseHTTPRequestHandler):
    # Match the response signature in the example
    server_version = "SimpleHTTP/0.6"
    sys_version = "Python/3.10.11"
    protocol_version = "HTTP/1.0"
    
    @classmethod
    def load_responses(cls):
        """Load responses from JSON file"""
        global responses
        if os.path.exists('responses.json'):
            with open('responses.json', 'r') as f:
                responses = json.load(f)
            print(f"Loaded {len(responses)} responses")
        else:
            raise FileNotFoundError("responses.json file not found")

    def do_GET(self):
        global response_index, responses
        if self.path != "/get":
            self.send_error(404)
            return

        # Get the next response in sequence (thread-safe)
        with lock:
            if response_index < len(responses):
                body = responses[response_index].encode('utf-8')
                current_index = response_index
                print(f"GET /get - Response {response_index + 1}/{len(responses)}: {responses[response_index]}")
                response_index += 1
            else:
                # If we've exhausted all responses, cycle back to the beginning
                body = responses[0].encode('utf-8')
                current_index = 0
                print(f"GET /get - Cycling back to response 1: {responses[0]}")
                response_index = 1

        self.send_response(200, "OK")
        self.send_header("Content-type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        global response_index, responses
        if self.path not in ["/", "/re"]:
            self.send_error(404)
            return

        try:
            length = int(self.headers.get('Content-Length', '0'))
        except ValueError:
            length = 0
        _ = self.rfile.read(length) if length > 0 else b""

        # Get the next response in sequence for POST requests too (thread-safe)
        with lock:
            if response_index < len(responses):
                body = responses[response_index].encode('utf-8')
                current_index = response_index
                print(f"POST {self.path} - Response {response_index + 1}/{len(responses)}: {responses[response_index]}")
                response_index += 1
            else:
                # If we've exhausted all responses, cycle back to the beginning
                body = responses[0].encode('utf-8')
                current_index = 0
                print(f"POST {self.path} - Cycling back to response 1: {responses[0]}")
                response_index = 1

        self.send_response(200, "OK")
        self.send_header("Content-type", "application/json")
        self.end_headers()
        self.wfile.write(body)


def run(host: str = "127.0.0.1", port: int = 8080) -> None:
    # Load responses before starting server
    LocalMimicHandler.load_responses()
    
    httpd = HTTPServer((host, port), LocalMimicHandler)
    print(f"Serving on http://{host}:{port}")
    print("Server will return responses in sequence from the captured traffic")
    httpd.serve_forever()


if __name__ == "__main__":
    run()


