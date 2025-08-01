from flask import Flask

app = Flask(__name__)

@app.route("/")
def home():
    return "Coming soon! Da Shboard of Conan. The Dashboard for Conan, The Botbarian."

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)