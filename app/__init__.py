"""
Initialisation de l'application Flask.
On utilise le pattern "application factory" pour garder le projet
propre et facilement testable (bonne pratique Flask).
"""

import os
from flask import Flask

# app/ est un sous-dossier du projet ; templates/ et static/ vivent
# à la racine, donc on doit indiquer leur chemin explicitement.
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def create_app():
    app = Flask(
        __name__,
        template_folder=os.path.join(BASE_DIR, "templates"),
        static_folder=os.path.join(BASE_DIR, "static"),
    )
    app.config["JSON_SORT_KEYS"] = False

    from .routes import main_bp
    app.register_blueprint(main_bp)

    return app
