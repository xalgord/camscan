#!/usr/bin/env python3
"""
h264dvr_viewer - Raw RTSP to Browser Stream Proxy for H264DVR Cameras

Bypasses the broken SDP negotiation in H264DVR firmware by performing
a manual RTSP handshake (DESCRIBE->SETUP->PLAY), depacketizing the
RTP H.264 stream, and serving decoded frames as MJPEG over HTTP.

Requires: python3, ffmpeg

Usage:
    python3 h264dvr_viewer.py <target> [options]

Examples:
    python3 h264dvr_viewer.py 192.168.1.100
    python3 h264dvr_viewer.py 10.0.0.5 -p 8554 -c 2 --sub
    python3 h264dvr_viewer.py 192.168.1.100 -u admin -w secret
    python3 h264dvr_viewer.py 192.168.1.100 --port 9999 --no-open
"""

import argparse
import io
import os
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler

__version__ = "1.0.0"

# ── Default credentials to try in order ──────────────────────────────
DEFAULT_CREDS = [
    ("admin", ""),
    ("admin", "admin"),
    ("admin", "12345"),
    ("admin", "123456"),
    ("admin", "888888"),
    ("admin", "666666"),
    ("user", "user"),
    ("default", "default"),
]

# ── Globals ──────────────────────────────────────────────────────────
current_frame = None
frame_lock = threading.Lock()
frame_event = threading.Event()
running = True
status_msg = "Starting..."
stats = {"frames": 0, "bytes_rx": 0, "connected_at": None, "creds": ("?", "?")}
args = None


# ═══════════════════════════════════════════════════════════════════════
# HTTP Server
# ═══════════════════════════════════════════════════════════════════════
class ViewerHandler(BaseHTTPRequestHandler):
    """Serves the viewer page, MJPEG stream, snapshots, and status API."""

    def log_message(self, *_):
        pass

    def do_GET(self):
        routes = {
            "/stream": self._mjpeg,
            "/snapshot": self._snapshot,
            "/api/status": self._api_status,
        }
        handler = routes.get(self.path.split("?")[0], self._page)
        handler()

    def _page(self):
        u, p = stats["creds"]
        html = f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>H264DVR Viewer - {args.target}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{background:#0d1117;color:#c9d1d9;font-family:'Segoe UI',system-ui,-apple-system,sans-serif;
  display:flex;flex-direction:column;align-items:center;min-height:100vh;padding:24px}}
.header{{text-align:center;margin-bottom:16px}}
h1{{font-size:1.2rem;font-weight:600;color:#f85149;letter-spacing:.5px;margin-bottom:4px}}
.meta{{font-size:.78rem;color:#8b949e}}
.meta span{{color:#58a6ff}}
.container{{position:relative;border:1px solid #30363d;border-radius:10px;overflow:hidden;
  background:#010409;max-width:960px;width:100%;box-shadow:0 8px 32px rgba(0,0,0,.4)}}
.container img{{width:100%;display:block;min-height:200px;background:#010409}}
.badge{{position:absolute;top:10px;left:10px;display:flex;align-items:center;gap:6px;
  background:rgba(248,81,73,.85);backdrop-filter:blur(4px);color:#fff;padding:3px 10px;
  border-radius:20px;font-size:.7rem;font-weight:700;letter-spacing:.5px}}
.dot{{width:6px;height:6px;border-radius:50%;background:#fff;animation:pulse 1.2s ease infinite}}
@keyframes pulse{{0%,100%{{opacity:1}}50%{{opacity:.25}}}}
.toolbar{{margin-top:12px;display:flex;gap:10px;flex-wrap:wrap;justify-content:center}}
.toolbar a,.toolbar button{{color:#58a6ff;font-size:.8rem;padding:6px 14px;border:1px solid #30363d;
  border-radius:6px;text-decoration:none;background:transparent;cursor:pointer;
  transition:border-color .2s,background .2s}}
.toolbar a:hover,.toolbar button:hover{{border-color:#58a6ff;background:rgba(88,166,255,.08)}}
#status{{margin-top:14px;font-size:.75rem;color:#8b949e;text-align:center;min-height:1.2em}}
.info-grid{{margin-top:16px;display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));
  gap:8px;max-width:480px;width:100%}}
.info-card{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:10px 14px;text-align:center}}
.info-card .label{{font-size:.65rem;color:#8b949e;text-transform:uppercase;letter-spacing:.5px}}
.info-card .value{{font-size:1rem;color:#c9d1d9;margin-top:2px;font-weight:600}}
footer{{margin-top:auto;padding-top:20px;font-size:.65rem;color:#484f58}}
</style>
</head><body>
<div class="header">
  <h1>H264DVR LIVE VIEWER</h1>
  <div class="meta"><span>{args.target}</span>:{args.rtsp_port} &middot; Channel {args.channel}</div>
</div>
<div class="container">
  <img id="feed" src="/stream" alt="Live Feed"
    onerror="setTimeout(()=>this.src='/stream?t='+Date.now(),2000)"/>
  <div class="badge"><div class="dot"></div>LIVE</div>
</div>
<div class="toolbar">
  <a href="/snapshot" target="_blank">&#128247; Snapshot</a>
  <button onclick="document.getElementById('feed').src='/stream?t='+Date.now()">&#128260; Reconnect</button>
  <a href="/stream" target="_blank">&#127916; Raw MJPEG</a>
</div>
<div id="status">Connecting...</div>
<div class="info-grid">
  <div class="info-card"><div class="label">Target</div><div class="value" id="v-target">{args.target}</div></div>
  <div class="info-card"><div class="label">Creds</div><div class="value" id="v-creds">--</div></div>
  <div class="info-card"><div class="label">Frames</div><div class="value" id="v-frames">0</div></div>
  <div class="info-card"><div class="label">Data RX</div><div class="value" id="v-data">0 KB</div></div>
</div>
<footer>CamScan H264DVR Viewer v{__version__}</footer>
<script>
setInterval(()=>{{
  fetch('/api/status').then(r=>r.json()).then(d=>{{
    document.getElementById('status').textContent=d.status;
    document.getElementById('v-creds').textContent=d.creds;
    document.getElementById('v-frames').textContent=d.frames;
    document.getElementById('v-data').textContent=d.data_rx;
  }}).catch(()=>{{}});
}},1500);
</script>
</body></html>"""
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(html.encode())

    def _mjpeg(self):
        self.send_response(200)
        self.send_header("Content-Type", "multipart/x-mixed-replace; boundary=frame")
        self.send_header("Cache-Control", "no-cache, no-store")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        try:
            while running:
                if frame_event.wait(timeout=3):
                    frame_event.clear()
                with frame_lock:
                    f = current_frame
                if f:
                    header = f"--frame\r\nContent-Type: image/jpeg\r\nContent-Length: {len(f)}\r\n\r\n"
                    self.wfile.write(header.encode() + f + b"\r\n")
                    self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass

    def _snapshot(self):
        with frame_lock:
            f = current_frame
        if f:
            self.send_response(200)
            self.send_header("Content-Type", "image/jpeg")
            self.send_header("Content-Disposition",
                             f'inline; filename="snapshot_{args.target}_{int(time.time())}.jpg"')
            self.end_headers()
            self.wfile.write(f)
        else:
            self.send_response(503)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"No frame yet - stream is buffering...")

    def _api_status(self):
        import json
        u, p = stats["creds"]
        data_kb = stats["bytes_rx"] / 1024
        data_str = f"{data_kb:.0f} KB" if data_kb < 1024 else f"{data_kb/1024:.1f} MB"
        body = json.dumps({
            "status": status_msg,
            "creds": f"{u}:{p or '(empty)'}",
            "frames": str(stats["frames"]),
            "data_rx": data_str,
        })
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body.encode())


# ═══════════════════════════════════════════════════════════════════════
# RTSP Client
# ═══════════════════════════════════════════════════════════════════════
def rtsp_connect(host, port, channel, stream_type, user, pwd):
    """Raw RTSP handshake. Returns connected socket or None."""
    path = f"/user={user}&password={pwd}&channel={channel}&stream={stream_type}.sdp"
    url = f"rtsp://{host}:{port}{path}"

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(8)
    s.connect((host, port))

    # DESCRIBE
    s.sendall((
        f"DESCRIBE {url} RTSP/1.0\r\n"
        f"CSeq: 1\r\n"
        f"Accept: application/sdp\r\n"
        f"User-Agent: CamScan/{__version__}\r\n\r\n"
    ).encode())
    time.sleep(0.4)
    resp = s.recv(4096).decode("utf-8", errors="replace")

    # Auth check
    if "401" in resp or "403" in resp:
        s.close()
        return None
    # H264DVR quirk: 200 + WWW-Authenticate = creds rejected
    if "200" in resp and "WWW-Authenticate" in resp:
        s.close()
        return None

    # SETUP
    s.sendall((
        f"SETUP {url}/trackID=1 RTSP/1.0\r\n"
        f"CSeq: 2\r\n"
        f"Transport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n"
        f"User-Agent: CamScan/{__version__}\r\n\r\n"
    ).encode())
    time.sleep(0.4)
    setup = s.recv(4096).decode("utf-8", errors="replace")
    if "200" not in setup:
        s.close()
        return None

    session = ""
    for line in setup.split("\n"):
        if "Session:" in line:
            session = line.split(":", 1)[1].strip().split(";")[0]

    # PLAY
    s.sendall((
        f"PLAY {url} RTSP/1.0\r\n"
        f"CSeq: 3\r\n"
        f"Session: {session}\r\n"
        f"Range: npt=0.000-\r\n"
        f"User-Agent: CamScan/{__version__}\r\n\r\n"
    ).encode())
    time.sleep(0.3)
    return s


# ═══════════════════════════════════════════════════════════════════════
# RTP Depacketizer
# ═══════════════════════════════════════════════════════════════════════
def depacketize(data, frag_buf):
    """Extract H.264 NAL units from RTP-over-TCP interleaved frames."""
    nals = b""
    pos = 0
    while pos < len(data):
        if data[pos:pos + 1] == b"$" and pos + 4 <= len(data):
            ch = data[pos + 1]
            ln = struct.unpack(">H", data[pos + 2:pos + 4])[0]
            end = pos + 4 + ln
            if end <= len(data) and ch == 0 and ln > 12:
                nal = data[pos + 16:end]  # $+ch+len(4) + RTP(12)
                if nal:
                    nt = nal[0] & 0x1F
                    nri = nal[0] & 0x60
                    if nt == 28 and len(nal) > 2:  # FU-A fragment
                        if nal[1] & 0x80:  # start
                            frag_buf[:] = [bytes([nri | (nal[1] & 0x1F)]) + nal[2:]]
                        elif frag_buf:
                            frag_buf[0] += nal[2:]
                        if nal[1] & 0x40 and frag_buf:  # end
                            nals += b"\x00\x00\x00\x01" + frag_buf[0]
                            frag_buf.clear()
                    elif nt in (1, 5, 6, 7, 8, 9):  # single NAL
                        nals += b"\x00\x00\x00\x01" + nal
            pos = end if end <= len(data) else pos + 1
            continue
        pos += 1
    return nals


def jpeg_splitter(pipe, callback):
    """Split continuous MJPEG output from ffmpeg into individual JPEG frames."""
    buf = b""
    while running:
        chunk = pipe.read(16384)
        if not chunk:
            break
        buf += chunk
        while True:
            soi = buf.find(b"\xff\xd8")
            if soi < 0:
                buf = buf[-1:]
                break
            eoi = buf.find(b"\xff\xd9", soi + 2)
            if eoi < 0:
                break
            frame = buf[soi:eoi + 2]
            buf = buf[eoi + 2:]
            if len(frame) > 500:
                callback(frame)


# ═══════════════════════════════════════════════════════════════════════
# Stream Worker
# ═══════════════════════════════════════════════════════════════════════
def stream_loop():
    """Main loop: authenticate -> stream -> decode -> serve. Auto-reconnects."""
    global current_frame, status_msg, running

    host = args.target
    port = args.rtsp_port
    channel = args.channel
    stream_type = 1 if args.sub else 0
    reconnect = args.reconnect

    # Build credential list
    if args.user:
        creds = [(args.user, args.password or "")]
    else:
        creds = list(DEFAULT_CREDS)

    while running:
        # ── Authentication ───────────────────────────────────────────
        sock = None
        working = None
        for u, p in creds:
            status_msg = f"Trying {u}:{p or '(empty)'}..."
            log(f"Trying {u}:{p or '(empty)'}")
            try:
                sock = rtsp_connect(host, port, channel, stream_type, u, p)
                if sock:
                    working = (u, p)
                    break
            except Exception as e:
                log(f"Error: {e}")

        if not sock:
            status_msg = f"All credentials failed. Retrying in {reconnect}s..."
            log("All credentials failed")
            time.sleep(reconnect)
            continue

        u, p = working
        stats["creds"] = working
        stats["connected_at"] = time.time()
        log(f"Authenticated as {u}:{p or '(empty)'}")
        log(f"Streaming {host}:{port} ch{channel} ({'sub' if stream_type else 'main'})")
        status_msg = f"Buffering stream..."

        # ── Persistent ffmpeg decoder ────────────────────────────────
        ffproc = subprocess.Popen(
            [
                "ffmpeg", "-loglevel", "error",
                "-f", "h264", "-i", "pipe:0",
                "-f", "mjpeg", "-q:v", str(args.quality),
                "-r", str(args.fps),
                "pipe:1",
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            bufsize=0,
        )

        def on_frame(jpg):
            global current_frame, status_msg
            with frame_lock:
                current_frame = jpg
            frame_event.set()
            stats["frames"] += 1
            elapsed = time.time() - (stats["connected_at"] or time.time())
            status_msg = (
                f"Live | {u}:{p or '(empty)'} | "
                f"{stats['frames']} frames | {elapsed:.0f}s uptime"
            )

        reader = threading.Thread(
            target=jpeg_splitter, args=(ffproc.stdout, on_frame), daemon=True
        )
        reader.start()

        # ── Receive loop ─────────────────────────────────────────────
        frag_buf = []
        try:
            while running:
                try:
                    data = sock.recv(65536)
                    if not data:
                        break
                    stats["bytes_rx"] += len(data)
                    h264 = depacketize(data, frag_buf)
                    if h264:
                        ffproc.stdin.write(h264)
                        ffproc.stdin.flush()
                except socket.timeout:
                    continue
                except Exception as e:
                    log(f"Stream error: {e}")
                    break
        except Exception as e:
            log(f"Loop error: {e}")

        # ── Cleanup ──────────────────────────────────────────────────
        for closeable in [ffproc.stdin, sock]:
            try:
                closeable.close()
            except Exception:
                pass
        try:
            ffproc.kill()
        except Exception:
            pass

        if running:
            status_msg = f"Disconnected. Reconnecting in {reconnect}s..."
            log(f"Reconnecting in {reconnect}s...")
            time.sleep(reconnect)


# ═══════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════
def log(msg):
    print(f"  [{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def main():
    global args, running

    parser = argparse.ArgumentParser(
        prog="h264dvr_viewer",
        description="Stream H264DVR cameras to your browser via raw RTSP proxy",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  %(prog)s 192.168.1.100                  # default creds, main stream
  %(prog)s 10.0.0.5 -p 8554 -c 2 --sub   # port 8554, channel 2, sub stream
  %(prog)s 192.168.1.100 -u admin -w pwd  # specific credentials
  %(prog)s 192.168.1.100 --http 8080      # serve on port 8080
        """,
    )
    parser.add_argument("target", help="Target IP or hostname")
    parser.add_argument("-p", "--port", dest="rtsp_port", type=int, default=554,
                        help="RTSP port (default: 554)")
    parser.add_argument("-c", "--channel", type=int, default=1,
                        help="Camera channel (default: 1)")
    parser.add_argument("-u", "--user", default=None,
                        help="Username (tries defaults if not set)")
    parser.add_argument("-w", "--password", default="",
                        help="Password (default: empty)")
    parser.add_argument("--sub", action="store_true",
                        help="Use sub-stream (lower quality, less bandwidth)")
    parser.add_argument("--http", type=int, default=9090,
                        help="HTTP server port (default: 9090)")
    parser.add_argument("--fps", type=int, default=10,
                        help="Max output FPS (default: 10)")
    parser.add_argument("--quality", type=int, default=4, choices=range(1, 10),
                        help="JPEG quality 1=best 9=worst (default: 4)")
    parser.add_argument("--reconnect", type=int, default=3,
                        help="Reconnect delay in seconds (default: 3)")
    parser.add_argument("--no-open", action="store_true",
                        help="Don't auto-open browser")
    parser.add_argument("-v", "--version", action="version",
                        version=f"%(prog)s {__version__}")
    args = parser.parse_args()

    banner = f"""
\033[91m╔══════════════════════════════════════════════════════╗
║        H264DVR Camera Viewer  \033[0mv{__version__}\033[91m              ║
╠══════════════════════════════════════════════════════╣\033[0m
  Target:   \033[96m{args.target}:{args.rtsp_port}\033[0m
  Channel:  \033[96m{args.channel}\033[0m ({'sub' if args.sub else 'main'} stream)
  Viewer:   \033[92mhttp://localhost:{args.http}\033[0m
  FPS:      {args.fps}  |  Quality: {args.quality}
\033[91m╚══════════════════════════════════════════════════════╝\033[0m"""
    print(banner, flush=True)

    # Check ffmpeg
    try:
        subprocess.run(["ffmpeg", "-version"], capture_output=True, timeout=3)
    except FileNotFoundError:
        print("\n  \033[91m[ERROR]\033[0m ffmpeg not found. Install it: sudo apt install ffmpeg")
        sys.exit(1)

    # Start stream worker
    worker = threading.Thread(target=stream_loop, daemon=True)
    worker.start()

    # Start HTTP server
    server = HTTPServer(("0.0.0.0", args.http), ViewerHandler)
    log(f"HTTP server on http://localhost:{args.http}")
    log("Ctrl+C to stop\n")

    # Auto-open browser
    if not args.no_open:
        threading.Timer(2.0, lambda: webbrowser.open(f"http://localhost:{args.http}")).start()

    def shutdown(*_):
        global running
        running = False
        print("\n", flush=True)
        log("Shutting down...")
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)
    server.serve_forever()


if __name__ == "__main__":
    main()
