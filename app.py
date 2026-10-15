"""Flask WSGI entry point used locally and by Vercel's Python runtime."""
from flask import Flask, jsonify, request, send_from_directory
from werkzeug.exceptions import RequestEntityTooLarge
from analyzer import analyze, MAX_UPLOAD

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = MAX_UPLOAD

@app.get('/')
def home():
    return send_from_directory('public', 'index.html')

@app.get('/<path:filename>')
def public_file(filename):
    return send_from_directory('public', filename)

@app.post('/api/analyze')
def analyze_capture():
    # Raw binary keeps request overhead below the Vercel body limit.
    if request.mimetype != 'application/octet-stream':
        return jsonify(error='Send the capture as application/octet-stream.'), 415
    try:
        return jsonify(analyze(request.get_data(cache=False)))
    except (ValueError, OverflowError) as exc:
        return jsonify(error=str(exc)), 400

@app.errorhandler(RequestEntityTooLarge)
def upload_too_large(error):
    return jsonify(error='Capture exceeds the 4 MB demo limit.'), 413

@app.after_request
def privacy_headers(response):
    if request.path.startswith('/api/'):
        response.headers['Cache-Control'] = 'no-store'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8000, debug=False)
