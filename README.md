# Malicious URL Detection

This project is a Flask-based web application that allows users to register, log in, and analyze URLs to determine if they are malicious. The application uses a Logistic Regression model trained on URL data to predict maliciousness.

## Features

- User registration and authentication using JWT
- URL analysis to predict maliciousness
- Feedback mechanism for users to report URL labels
- Model retraining based on user feedback
- Secure endpoints for user operations

## Technologies Used

- **Flask**: Web framework for building the API
- **Flask-SQLAlchemy**: ORM for database management
- **Flask-Bcrypt**: For password hashing
- **Flask-JWT-Extended**: For managing JSON Web Tokens
- **Pandas**: Data manipulation and analysis
- **Scikit-learn**: For machine learning model training and evaluation
- **SQLite**: Lightweight database for storing user information and feedback

## Getting Started

### Prerequisites

Make sure you have Python 3.x installed. You will also need the following libraries:

```bash
pip install Flask Flask-SQLAlchemy Flask-Bcrypt Flask-JWT-Extended pandas scikit-learn
