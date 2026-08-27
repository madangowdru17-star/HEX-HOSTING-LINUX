from flask import Blueprint, render_template, jsonify

from extensions import get_db

bp = Blueprint("public", __name__)


@bp.route("/")
def home():
    return render_template("index.html")


@bp.route("/api/announcement")
def get_announcement():
    db = get_db()
    conf = db.execute(
        "SELECT popup_title, popup_msg, popup_img, show_popup FROM admin_settings WHERE id=1"
    ).fetchone()
    db.close()
    return jsonify(dict(conf) if conf else {})
