from chat import get_response
from flask import Flask
from flask import render_template, jsonify, request
# from flask_cors import CORS

app = Flask(__name__)
# CORS(app)

@app.get("/")
def index_get():
    return render_template("base.html")

@app.post("/predict")
def predict():
    text = request.get_json().get("message")
    response = get_response(text)
    message = {"answer":response}
    return jsonify(message)

if __name__ == "__main__":
    app.run(debug=True)




# <script>
#         $SCRIPT_ROOT = {{ request.script_root|tojson }};
#     </script>
#     <script type ="text/javascript" src = "{{ url_for('static', filename='app.js') }}"> </script>