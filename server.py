from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from api.analyze import handler
class Local(SimpleHTTPRequestHandler):
    def __init__(self,*args,**kwargs): super().__init__(*args,directory=str(Path(__file__).parent/'public'),**kwargs)
    def do_POST(self):
        if self.path=='/api/analyze': handler.do_POST(self)
        else: self.send_error(404)
if __name__=='__main__':
    print('net-traffic-analyzer → http://localhost:8000',flush=True)
    ThreadingHTTPServer(('127.0.0.1',8000),Local).serve_forever()
