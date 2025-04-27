from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
emails = [
    "Your account has been suspended. Click here to verify your info.",
    "Meeting scheduled for tomorrow at 10 AM.",
    "Urgent: Update your payment details immediately!",
    "Lunch plans for today?"
]
labels = [1, 0, 1, 0]
vectorizer = TfidfVectorizer(stop_words='english')
X = vectorizer.fit_transform(emails)

model = LogisticRegression()
model.fit(X, labels)

new_email = ["Please verify your account now."]
new_vec = vectorizer.transform(new_email)
prediction = model.predict(new_vec)

print("Phishing" if prediction[0] == 1 else "Legitimate")