import os
import base64

print("Inlining resources...")

# Define paths
base_dir = os.path.dirname(os.path.abspath(__file__))
www_dir = os.path.join(base_dir, 'www')
pkg_dir = os.path.join(www_dir, 'pkg')

# Load styles
with open(os.path.join(www_dir, 'style.css'), 'r') as f:
    style_content = f.read()

# Load app js
with open(os.path.join(www_dir, 'app.js'), 'r') as f:
    app_content = f.read()

# Load compiled JS bindings
with open(os.path.join(pkg_dir, 'sovereign_wallet.js'), 'r') as f:
    js_bindings = f.read()

# Load compiled WASM and base64 encode it
with open(os.path.join(pkg_dir, 'sovereign_wallet_bg.wasm'), 'rb') as f:
    wasm_bytes = f.read()
    wasm_base64 = base64.b64encode(wasm_bytes).decode('utf-8')

# Modify JS bindings to load from inline base64 instead of URL fetch
wasm_init_override = f"""
const wasmBase64 = "{wasm_base64}";
const wasmBytes = Uint8Array.from(atob(wasmBase64), c => c.charCodeAt(0));
"""

# Replace the URL initialization line with our inline bytes
target_line = "input = new URL('sovereign_wallet_bg.wasm', import.meta.url);"
if target_line in js_bindings:
    js_bindings = js_bindings.replace(target_line, "input = wasmBytes;")
else:
    # Fallback if wasm-pack format is slightly different
    js_bindings = js_bindings.replace("init(input)", "init(wasmBytes)")

full_js = wasm_init_override + "\n" + js_bindings + "\n" + app_content

# Read template
with open(os.path.join(www_dir, 'template.html'), 'r') as f:
    template = f.read()

# Replace placeholders
output = template.replace("/* STYLE_CSS */", style_content)
output = output.replace("/* APP_JS */", full_js)

# Ensure app directory exists
app_dir = os.path.join(base_dir, 'app')
os.makedirs(app_dir, exist_ok=True)

# Write output to index.html in the app folder
with open(os.path.join(app_dir, 'index.html'), 'w') as f:
    f.write(output)

# Copy README.md if it exists
readme_src = os.path.join(base_dir, 'README.md')
if os.path.exists(readme_src):
    with open(readme_src, 'r') as f_in:
        with open(os.path.join(app_dir, 'README.md'), 'w') as f_out:
            f_out.write(f_in.read())

# Copy or create faq.html in the app folder
faq_src = os.path.join(www_dir, 'faq.html')
if os.path.exists(faq_src):
    with open(faq_src, 'r') as f_in:
        with open(os.path.join(app_dir, 'faq.html'), 'w') as f_out:
            f_out.write(f_in.read())
else:
    # Create a basic faq.html template if missing
    with open(os.path.join(app_dir, 'faq.html'), 'w') as f_out:
        f_out.write("<h1>Sovereign Wallet FAQ</h1><p>Frequently Asked Questions.</p>")

# Copy run-local-server.sh to the app folder and make it executable
script_src = os.path.join(base_dir, 'run-local-server.sh')
if os.path.exists(script_src):
    script_dest = os.path.join(app_dir, 'run-local-server.sh')
    with open(script_src, 'r') as f_in:
        with open(script_dest, 'w') as f_out:
            f_out.write(f_in.read())
    try:
        os.chmod(script_dest, 0o755)
    except Exception as e:
        print(f"Warning: Could not set execution permissions on run-local-server.sh: {e}")

# Copy run-local-server.bat to the app folder
bat_src = os.path.join(base_dir, 'run-local-server.bat')
if os.path.exists(bat_src):
    bat_dest = os.path.join(app_dir, 'run-local-server.bat')
    with open(bat_src, 'r') as f_in:
        with open(bat_dest, 'w') as f_out:
            f_out.write(f_in.read())

print("✅ Single-file index.html and app assets built successfully inside app/ directory!")
