from flask import Flask, jsonify
from flask_cors import CORS

from config import CORS_ORIGINS, FLASK_DEBUG, PORT
from database import init_db
from routes.logs      import logs_bp
from routes.alerts    import alerts_bp
from routes.stats     import stats_bp
from routes.detection import detection_bp

app = Flask(__name__)
CORS(app, origins=CORS_ORIGINS)
init_db()

app.register_blueprint(logs_bp,      url_prefix="/api")
app.register_blueprint(alerts_bp,    url_prefix="/api")
app.register_blueprint(stats_bp,     url_prefix="/api")
app.register_blueprint(detection_bp, url_prefix="/api")


@app.route("/api/health", methods=["GET"])
def health():
    """Endpoint de santé utilisé par le healthcheck Docker."""
    return jsonify({"status": "ok"}), 200


if __name__ == "__main__":
    app.run(debug=FLASK_DEBUG, port=PORT, host="0.0.0.0")
