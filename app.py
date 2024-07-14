from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import pickle
import pandas as pd
import os

with open('lr_model.pkl', 'rb') as model_file:
    lr_model = pickle.load(model_file)
with open('vectorizer.pkl', 'rb') as vec_file:
    vectorizer = pickle.load(vec_file)
with open('training_data.pkl', 'rb') as train_file:
    X_train_tfidf, y_train = pickle.load(train_file)

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    email = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)

class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(500), nullable=False)
    label = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class URLAnalysis(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(500), nullable=False)
    maliciousness_score = db.Column(db.Float, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

with app.app_context():
    db.create_all()

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    new_user = User(username=data['username'], email=data['email'], password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"status": "success", "userId": new_user.id})

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    if user and bcrypt.check_password_hash(user.password, data['password']):
        token = create_access_token(identity=user.id)
        return jsonify({"status": "success", "token": token})
    return jsonify({"status": "failure", "message": "Invalid credentials"}), 401

@app.route('/api/logout', methods=['POST'])
@jwt_required()
def logout():
    return jsonify({"status": "success", "message": "Logged out"}), 200

@app.route('/api/analyze', methods=['POST'])
@jwt_required()
def analyze_url():
    data = request.get_json()
    user_id = get_jwt_identity()
    url = data['url']
    url_tfidf = vectorizer.transform([url])
    prediction = lr_model.predict_proba(url_tfidf)[0][1]

    new_analysis = URLAnalysis(url=url, maliciousness_score=prediction, user_id=user_id)
    db.session.add(new_analysis)
    db.session.commit()

    return jsonify({"url": url, "maliciousness_score": prediction})

@app.route('/api/feedback', methods=['POST'])
@jwt_required()
def feedback():
    data = request.get_json()
    user_id = get_jwt_identity()
    new_feedback = Feedback(url=data['url'], label=data['label'], user_id=user_id)
    db.session.add(new_feedback)
    db.session.commit()
    feedback_count = Feedback.query.count()
    if feedback_count >= 10:
        retrain_model()
        db.session.query(Feedback).delete()
        db.session.commit()

    return jsonify({"status": "success"})

@app.route('/api/users', methods=['GET'])
@jwt_required()
def get_users():
    users = User.query.all()
    user_list = [{"id": user.id, "username": user.username, "email": user.email} for user in users]
    return jsonify({"users": user_list})

@app.route('/api/urls', methods=['GET'])
@jwt_required()
def get_urls():
    analyses = URLAnalysis.query.all()
    url_list = [{"id": analysis.id, "url": analysis.url, "maliciousness_score": analysis.maliciousness_score} for analysis in analyses]
    return jsonify({"urls": url_list})

@app.route('/api/user/<int:user_id>', methods=['DELETE'])
@jwt_required()
def delete_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({"status": "failure", "message": "User not found"}), 404
    

    URLAnalysis.query.filter_by(user_id=user_id).delete()
    db.session.delete(user)
    db.session.commit()
    return jsonify({"status": "success", "message": "User and all associated URLs deleted"})

@app.route('/api/url/<int:url_id>', methods=['DELETE'])
@jwt_required()
def delete_url(url_id):
    analysis = URLAnalysis.query.get(url_id)
    if not analysis:
        return jsonify({"status": "failure", "message": "URL not found"}), 404
    
    db.session.delete(analysis)
    db.session.commit()
    return jsonify({"status": "success", "message": "URL analysis deleted"})

@app.route('/api/upload_model', methods=['POST'])
@jwt_required()
def upload_model():
    if 'model' not in request.files:
        return jsonify({"status": "failure", "message": "No model file part in the request"}), 400
    
    model_file = request.files['model']
    vectorizer_file = request.files['vectorizer']
    training_data_file = request.files['training_data']

    model_file.save('lr_model.pkl')
    vectorizer_file.save('vectorizer.pkl')
    training_data_file.save('training_data.pkl')

    global lr_model, vectorizer, X_train_tfidf, y_train
    with open('lr_model.pkl', 'rb') as model_f:
        lr_model = pickle.load(model_f)
    with open('vectorizer.pkl', 'rb') as vec_f:
        vectorizer = pickle.load(vec_f)
    with open('training_data.pkl', 'rb') as train_f:
        X_train_tfidf, y_train = pickle.load(train_f)

    return jsonify({"status": "success", "message": "Model updated successfully"})

def retrain_model():
    feedbacks = Feedback.query.all()
    if not feedbacks:
        return

    feedback_data = [(feedback.url, feedback.label) for feedback in feedbacks]
    feedback_df = pd.DataFrame(feedback_data, columns=['url', 'label'])
    X_feedback = vectorizer.transform(feedback_df['url'])
    y_feedback = feedback_df['label']

    X_combined = pd.concat([pd.DataFrame(X_train_tfidf.toarray()), pd.DataFrame(X_feedback.toarray())], axis=0)
    y_combined = pd.concat([pd.Series(y_train), y_feedback], axis=0)

    lr_model.fit(X_combined, y_combined)
    print("Model retrained with feedback data.")

    with open('lr_model.pkl', 'wb') as model_file:
        pickle.dump(lr_model, model_file)

if __name__ == '__main__':
    app.run(debug=True)
