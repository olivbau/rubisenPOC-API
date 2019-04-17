import os
from app import db
from passlib.hash import bcrypt
from sklearn.neighbors import LocalOutlierFactor
from sklearn.externals import joblib
from utils import encrypt_file
from dotenv import load_dotenv
import pyAesCrypt

class UserModel(db.Model):
    __tablename__ = 'emails'

    id = db.Column(db.Integer, primary_key = True)
    email = db.Column(db.String(120), unique = True, nullable = False)
    password = db.Column(db.String(120), nullable = False)
    model_id = db.Column(db.String(120), unique = True, nullable = False)
    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    def create_model(self, X_train):
        clf = LocalOutlierFactor(contamination='auto', novelty=True, algorithm='auto')
        clf.fit(X_train)
        joblib.dump(clf, './models/%s.pkl'% (self.model_id))

    @classmethod
    def find_by_email(cls, email):
        return cls.query.filter_by(email = email).first()

    @classmethod
    def return_all(cls):
        def to_json(x):
            return {
                'email': x.email,
                'password': x.password
            }
        return {'users': list(map(lambda x: to_json(x), UserModel.query.all()))}
    
    @staticmethod
    def generate_hash(password):
        return bcrypt.hash(password)
    @staticmethod
    def verify_hash(password, hash):
        return bcrypt.verify(password, hash)
    @staticmethod
    def verify_model(modelId, X_test):
        clf = joblib.load('models/%s.pkl'% (modelId))
        prediction = clf.predict([X_test])[0]
        return prediction == 1

class RevokedTokenModel(db.Model):
    __tablename__ = 'revoked_tokens'
    id = db.Column(db.Integer, primary_key = True)
    jti = db.Column(db.String(120))
    
    def add(self):
        db.session.add(self)
        db.session.commit()
    
    @classmethod
    def is_jti_blacklisted(cls, jti):
        query = cls.query.filter_by(jti = jti).first()
        return bool(query)