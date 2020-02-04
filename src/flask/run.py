import os
from flask import Flask
from flask_restful import Api
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager

app = Flask(__name__)
api = Api(app)

app.config["SQLALCHEMY_DATABASE_URI"] = os.environ["connection_string"]
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["JWT_SECRET_KEY"] = os.environ["jwt_secret"]
app.config["JWT_BLACKLIST_ENABLED"] = True
app.config["JWT_BLACKLIST_TOKEN_CHECKS"] = ["access", "refresh"]

db = SQLAlchemy(app)
jwt = JWTManager(app)

import views, models, resources

@app.before_first_request
def create_tables():
    db.create_all()
    if not models.UserModel.find_by_username(os.environ["admin_user"]):
        admin_user = models.UserModel(
            username = os.environ["admin_user"],
            access_level = "ADMIN",
            password = models.UserModel.generate_hash(os.environ["admin_password"])
        )
        admin_user.save_to_db()

@jwt.token_in_blacklist_loader
def check_if_token_in_bl(decrypted_token):
    jti = decrypted_token["jti"]
    return models.RevokedTokenModel.is_jti_blacklisted(jti)

api.add_resource(resources.Register, "/register")
api.add_resource(resources.Login, "/login")
api.add_resource(resources.LogoutAccess, "/logoutaccess")
api.add_resource(resources.LogoutRefresh, "/logoutrefresh")
api.add_resource(resources.TokenRefresh, "/refresh")
api.add_resource(resources.GetUsers, "/users")
api.add_resource(resources.GetLog, "/modsec")
