from re import fullmatch
import json
import uuid
from flask_restful import Resource, reqparse
from models import UserModel, RevokedTokenModel
from flask_jwt_extended import (create_access_token, create_refresh_token, jwt_required, jwt_refresh_token_required, get_jwt_identity, get_raw_jwt)

parserRegister = reqparse.RequestParser()
parserRegister.add_argument('email', help = 'This field cannot be blank', required = True)
parserRegister.add_argument('password', help = 'This field cannot be blank', required = True)
parserRegister.add_argument('train', help = 'This field cannot be blank', required = True)

parserLogin = reqparse.RequestParser()
parserLogin.add_argument('email', help = 'This field cannot be blank', required = True)
parserLogin.add_argument('password', help = 'This field cannot be blank', required = True)
parserLogin.add_argument('test', help = 'This field cannot be blank', required = True)


class UserRegistration(Resource):
    def post(self):
        data = parserRegister.parse_args()
        if UserModel.find_by_email(data['email']):
            return {'message': 'User with email {} already exists'.format(data['email'])}, 409
        
        if not fullmatch(r"[^@]+@[^@]+\.[^@]+", data['email']):
           return {'message': 'Email address {} is not valid'.format(data['email'])}, 400

        new_user = UserModel(
            email = data['email'],
            password = UserModel.generate_hash(data['password']),
            model_id = uuid.uuid4().hex
        )
        
        try:
            new_user.save_to_db()
            new_user.create_model(json.loads(data['train']))
            return {
                'message': 'User {} was created'.format(data['email']),
            }
        except Exception as e:
            print(e)
            return {'message': 'Something went wrong'}, 500


class UserLogin(Resource):
    def post(self):
        data = parserLogin.parse_args()
        current_user = UserModel.find_by_email(data['email'])

        if not current_user:
            return {'message': 'User {} doesn\'t exist'.format(data['email']), 'login': False}, 400
        elif not UserModel.verify_hash(data['password'], current_user.password):
            return {'message': 'Wrong credentials or bad behaviour', 'login': False}, 401
        elif not UserModel.verify_model(current_user.model_id, json.loads(data['test'])):
            return {'message': 'Wrong credentials or bad behaviour', 'login': False}, 401
        else:
            access_token = create_access_token(identity = data['email'])
            refresh_token = create_refresh_token(identity = data['email'])
            return {
                'login': True,
                'access_token': access_token,
                'refresh_token': refresh_token
            }, 200
      
class UserLogoutAccess(Resource):
    @jwt_required
    def post(self):
        jti = get_raw_jwt()['jti']
        try:
            revoked_token = RevokedTokenModel(jti = jti)
            revoked_token.add()
            return {'message': 'Access token has been revoked'}
        except:
            return {'message': 'Something went wrong'}, 500


class UserLogoutRefresh(Resource):
    @jwt_refresh_token_required
    def post(self):
        jti = get_raw_jwt()['jti']
        try:
            revoked_token = RevokedTokenModel(jti = jti)
            revoked_token.add()
            return {'message': 'Refresh token has been revoked'}
        except:
            return {'message': 'Something went wrong'}, 500
      
      
class TokenRefresh(Resource):
    @jwt_refresh_token_required
    def post(self):
        current_user = get_jwt_identity()
        access_token = create_access_token(identity = current_user)
        return {'access_token': access_token}
      
      
class AllUsers(Resource):
    def get(self):
        return UserModel.return_all()
      



class SecretResource(Resource):
    @jwt_required
    def get(self):
        return {
            'answer': 42
        }