"""Flask WSGI entry point used locally and by Vercel's Python runtime."""
from flask import Flask, Request, jsonify, request, send_from_directory
from io import BytesIO
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge
from analyzer import analyze, MAX_UPLOAD

class MemoryUploadRequest(Request):
    # Werkzeug otherwise spools larger multipart files to temporary disk.
    def _get_file_stream(self, total_content_length, content_type, filename=None, content_length=None):
        return BytesIO()

app = Flask(__name__)
app.request_class = MemoryUploadRequest
app.config.update(MAX_CONTENT_LENGTH=MAX_UPLOAD + 65_536,
                  MAX_FORM_MEMORY_SIZE=65_536, MAX_FORM_PARTS=4)

@app.get('/')
def home():
    return send_from_directory('public', 'index.html')

@app.get('/<path:filename>')
def public_file(filename):
    return send_from_directory('public', filename)

@app.post('/upload')
def upload_capture():
    if request.mimetype != 'multipart/form-data':
        return jsonify(error='Upload a capture using the multipart file field.'), 415
    files = request.files.getlist('file')
    if len(files) != 1:
        return jsonify(error='Choose exactly one capture in the file field.'), 400
    upload = files[0]
    filename = secure_filename(upload.filename or '')
    if not filename.lower().endswith(('.pcap', '.pcapng')):
        return jsonify(error='Choose a .pcap or .pcapng file.'), 400
    try:
        # Bound file reads independently of the multipart request overhead.
        data = upload.stream.read(MAX_UPLOAD + 1)
        if len(data) > MAX_UPLOAD:
            raise RequestEntityTooLarge()
        return jsonify(filename=filename, **analyze(data))
    except (ValueError, OverflowError) as exc:
        return jsonify(error=str(exc)), 400

@app.post('/api/analyze')
def analyze_capture():
    # Raw binary keeps request overhead below the Vercel body limit.
    if request.mimetype != 'application/octet-stream':
        return jsonify(error='Send the capture as application/octet-stream.'), 415
    if request.content_length and request.content_length > MAX_UPLOAD:
        raise RequestEntityTooLarge()
    try:
        return jsonify(analyze(request.get_data(cache=False)))
    except (ValueError, OverflowError) as exc:
        return jsonify(error=str(exc)), 400

@app.errorhandler(RequestEntityTooLarge)
def upload_too_large(error):
    return jsonify(error='Capture exceeds the 4 MB demo limit.'), 413

@app.after_request
def privacy_headers(response):
    if request.path.startswith('/api/') or request.path == '/upload':
        response.headers['Cache-Control'] = 'no-store'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8000, debug=False)
