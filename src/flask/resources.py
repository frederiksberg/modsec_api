from flask_restful import Resource, reqparse
from flask_jwt_extended import (create_access_token, create_refresh_token, jwt_required,
    jwt_refresh_token_required, get_jwt_identity, get_raw_jwt)
from models import UserModel, RevokedTokenModel
import lib

parser = reqparse.RequestParser()
parser.add_argument("username", help="This field is required", required=True)
parser.add_argument("password", help="This field is required", required=True)

class Register(Resource):
    @jwt_required
    def post(self):
        req_user = UserModel.find_by_username(get_jwt_identity())
        if not req_user:
            return {"message": "Invalid token"}

        if req_user.access_level != "ADMIN":
            return {"message": "Your current user does not have the required priviledges"}

        data = parser.parse_args()

        if UserModel.find_by_username(data["username"]):
            return {"message": f"User {data['username']} already exists"}

        new_user = UserModel(
            username = data["username"],
            access_level = "USER",
            password = UserModel.generate_hash(data["password"])
        )

        try:
            new_user.save_to_db()
            access_token = create_access_token(identity = data["username"])
            refresh_token = create_refresh_token(identity = data["username"])
            return {
                "message": f"User {data['username']} was created!",
                "access_token": access_token,
                "refresh_token": refresh_token
            }
        except:
            return {"message": "An error occured while creating user"}

class Login(Resource):
    def post(self):
        data = parser.parse_args()
        current_user = UserModel.find_by_username(data["username"])

        if not current_user:
            return {"message": "Incorrent username or password"}

        if UserModel.verify_hash(data["password"], current_user.password):
            access_token = create_access_token(identity = data["username"])
            refresh_token = create_refresh_token(identity = data["username"])
            return {
                "message": f"Logged in as {data['username']}!",
                "access_token": access_token,
                "refresh_token": refresh_token
            }
        else:
            return {"message": "Incorrent username or password"}

class LogoutAccess(Resource):
    @jwt_required
    def post(self):
        jti = get_raw_jwt()["jti"]
        try:
            revoked_token = RevokedTokenModel(jti = jti)
            revoked_token.add()
            return {"message": "Access token has been revoked"}
        except:
            return {"message": "An error occured while revoking token"}

class LogoutRefresh(Resource):
    @jwt_refresh_token_required
    def post(self):
        jti = get_raw_jwt()["jti"]
        try:
            revoked_token = RevokedTokenModel(jti = jti)
            revoked_token.add()
            return {"message": "Refresh token has been revoked"}
        except:
            return {"message": "An error occured while revoking token"}

class GetUsers(Resource):
    @jwt_required
    def get(self):
        return UserModel.return_all()

class TokenRefresh(Resource):
    @jwt_refresh_token_required
    def post(self):
        current_user = get_jwt_identity()
        access_token = create_access_token(identity = current_user)
        return {"access_token": access_token}

class GetLog(Resource):
    @jwt_required
    def get(self):
        a = lib.Audit("/var/log/modsec_audit.log")
        return a.ToDict()
