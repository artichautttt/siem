from flask import Flask
from flask_cors import CORS
from database import init_db
from routes.logs    import logs_bp
from routes.alerts  import alerts_bp
from routes.stats   import stats_bp

app = Flask(__name__)
CORS(app)

init_db()

app.register_blueprint(logs_bp,   url_prefix="/api")
app.register_blueprint(alerts_bp, url_prefix="/api")
app.register_blueprint(stats_bp,  url_prefix="/api")

if __name__ == "__main__":
    app.run(debug=True, port=5000)
