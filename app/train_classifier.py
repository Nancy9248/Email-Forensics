"""
Trains a phishing-email text classifier using the public labeled dataset.
Uses TF-IDF (turns email text into weighted word-importance vectors) +
Logistic Regression (fast, explainable — gives a probability, not just
a hard yes/no, which is important for a confidence-based fraud score).
Saves the trained model + vectorizer to disk so the Flask app can load
them instantly without retraining every time.
"""

import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, accuracy_score
import joblib
import os

DATA_PATH = "samples/phishing_dataset.csv"
MODEL_DIR = "models"


def train():
    df = pd.read_csv(DATA_PATH)

    # Drop any rows with missing text (real-world datasets often have a few)
    df = df.dropna(subset=["Email Text", "Email Type"])

    X = df["Email Text"]
    y = df["Email Type"].map({"Safe Email": 0, "Phishing Email": 1})

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # TF-IDF: converts text into numbers based on word importance.
    # stop_words='english' removes common filler words (the, is, and...).
    # max_features caps vocabulary size so the model stays fast and light.
    vectorizer = TfidfVectorizer(stop_words="english", max_features=5000)
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)

    model = LogisticRegression(max_iter=1000)
    model.fit(X_train_vec, y_train)

    predictions = model.predict(X_test_vec)
    accuracy = accuracy_score(y_test, predictions)

    print(f"Test accuracy: {accuracy:.2%}\n")
    print(classification_report(y_test, predictions, target_names=["Safe", "Phishing"]))

    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(model, os.path.join(MODEL_DIR, "phishing_classifier.joblib"))
    joblib.dump(vectorizer, os.path.join(MODEL_DIR, "tfidf_vectorizer.joblib"))
    print(f"\nModel and vectorizer saved to {MODEL_DIR}/")


if __name__ == "__main__":
    train()