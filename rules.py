def calculate_risk(features):

    score = 0
    reasons = []

    # 1. HTTPS
    if not features["https"]:
        score += 2
        reasons.append("HTTPS is not used")

    # 2. Very long URL
    if features["url_length"] > 75:
        score += 1
        reasons.append("URL is unusually long")

    # 3. IP address
    if features["has_ip"]:
        score += 3
        reasons.append("IP address is used instead of a domain name")

    # 4. Suspicious keywords
    if features["keyword_count"] >= 1:
        score += 2
        reasons.append(
            "Suspicious keyword(s): "
            + ", ".join(features["suspicious_keywords"])
        )

    # 5. Too many dots
    if features["dot_count"] >= 4:
        score += 1
        reasons.append("Large number of dots/subdomains")

    # 6. Too many hyphens
    if features["hyphen_count"] >= 4:
        score += 1
        reasons.append("Large number of hyphens")

    # 7. Special characters
    if features["special_character_count"] >= 4:
        score += 1
        reasons.append("Many special characters are present")

    # 8. @ symbol
    if features["has_at_symbol"]:
        score += 3
        reasons.append("@ symbol can hide the actual destination")

    # 9. URL shortening
    if features["is_shortened"]:
        score += 2
        reasons.append("URL shortening service detected")

    # 10. Double slash
    if features["double_slash"]:
        score += 1
        reasons.append("Unusual double slash detected in URL path")

    # Classification
    if score >= 6:
        classification = "PHISHING"

    elif score >= 3:
        classification = "SUSPICIOUS"

    else:
        classification = "LEGITIMATE"

    return classification, score, reasons