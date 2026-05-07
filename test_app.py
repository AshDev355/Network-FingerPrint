from flask import Flask, render_template_string

app = Flask(__name__)

@app.route('/')
def home():
    return '''
    <h1>✅ Flask is Working!</h1>
    <p>If you see this, your server is running correctly.</p>
    <a href="/test">Test JSON API</a>
    '''

@app.route('/test')
def test():
    return {"status": "working", "message": "API is functional"}

if __name__ == '__main__':
    print("Test server running at http://127.0.0.1:5000")
    app.run(debug=True, host='127.0.0.1', port=5000)