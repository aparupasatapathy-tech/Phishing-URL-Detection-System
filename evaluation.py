import pandas as pd

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)

from url_analyzer import extract_features
from rules import calculate_risk


df = pd.read_csv("dataset/test_urls.csv")


actual = []
predicted = []


for _, row in df.iterrows():

    url = row["URL"]

    features = extract_features(url)

    result, score, reasons = calculate_risk(features)

    actual.append(
        row["Actual"].lower()
    )

    predicted.append(
        result.lower()
    )


# Convert 3 classes into binary:
# phishing = 1
# everything else = 0

actual_binary = [
    1 if x == "phishing" else 0
    for x in actual
]

predicted_binary = [
    1 if x == "phishing" else 0
    for x in predicted
]


accuracy = accuracy_score(
    actual_binary,
    predicted_binary
)

precision = precision_score(
    actual_binary,
    predicted_binary,
    zero_division=0
)

recall = recall_score(
    actual_binary,
    predicted_binary,
    zero_division=0
)

f1 = f1_score(
    actual_binary,
    predicted_binary,
    zero_division=0
)


print("\n===== PERFORMANCE =====")

print(
    "Accuracy :",
    round(accuracy * 100, 2),
    "%"
)

print(
    "Precision:",
    round(precision * 100, 2),
    "%"
)

print(
    "Recall   :",
    round(recall * 100, 2),
    "%"
)

print(
    "F1 Score :",
    round(f1 * 100, 2),
    "%"
)


print("\n===== CONFUSION MATRIX =====")

cm = confusion_matrix(
    actual_binary,
    predicted_binary
)

print(cm)


print("\n===== CLASSIFICATION REPORT =====")

print(
    classification_report(
        actual_binary,
        predicted_binary,
        target_names=[
            "Legitimate/Suspicious",
            "Phishing"
        ],
        zero_division=0
    )
)