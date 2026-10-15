"""Bounded payload formatting for explicit packet drill-down."""
PREVIEW_BYTES = 128
MAX_PREVIEW_PACKETS = 1500


def preview_payload(payload, captured_length):
    prefix = payload[:PREVIEW_BYTES]
    return dict(hex=prefix.hex(' '), ascii=''.join(chr(b) if 32 <= b < 127 else '.' for b in prefix),
                payloadLength=len(payload), previewLength=len(prefix), capturedLength=captured_length,
                truncated=len(payload) > len(prefix))
