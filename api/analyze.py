from http.server import BaseHTTPRequestHandler
import json
from analyzer import analyze, MAX_UPLOAD
class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            size=int(self.headers.get('Content-Length','0'))
            if size<=0 or size>MAX_UPLOAD: raise ValueError('Choose a capture between 1 byte and 4 MB.')
            result=analyze(self.rfile.read(size)); status=200
        except (ValueError, OverflowError) as exc:
            result={'error':str(exc)}; status=400
        payload=json.dumps(result).encode()
        self.send_response(status); self.send_header('Content-Type','application/json'); self.send_header('Cache-Control','no-store'); self.end_headers(); self.wfile.write(payload)
