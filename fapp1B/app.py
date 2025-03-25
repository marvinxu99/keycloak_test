from flask import Flask
from config import Config
from auth import init_auth 
from auth.routes import auth_bp
from user.routes import user_bp
from main.routes import main_bp


app = Flask(__name__)
app.config.from_object(Config)

init_auth(app)

# Register Blueprints
app.register_blueprint(main_bp)
app.register_blueprint(auth_bp)
app.register_blueprint(user_bp)

if __name__ == "__main__":
    app.run(port=5001, debug=True)
