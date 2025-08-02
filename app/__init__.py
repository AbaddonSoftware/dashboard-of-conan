from flask import Flask

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'your_secret' # TODO: secure

    from .routes import main
    app.register_blueprint(main)    

    return app
