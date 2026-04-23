from flask import Flask
from flask_cors import CORS
from database import init_db
from routes.logs import logs_bp

app = Flask(__name__)
CORS(app)  # Autorise les requêtes depuis Angular (localhost:4200)

# Initialise la base de données au démarrage
init_db()

# Enregistre les routes
app.register_blueprint(logs_bp, url_prefix="/api")

if __name__ == "__main__":
    app.run(debug=True, port=5000)
