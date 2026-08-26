

import argparse
import math
import re
from dataclasses import dataclass
from getpass import getpass


COMMON_PASSWORDS = {
    "123456",
    "12345678",
    "123456789",
    "abc123",
    "admin",
    "iloveyou",
    "letmein",
    "password",
    "password1",
    "password123",
    "qwerty",
    "welcome",
}

ORDERED_PATTERNS = (
    "abcdefghijklmnopqrstuvwxyz",
    "0123456789",
)

KEYBOARD_PATTERNS = (
    "qwerty",
    "asdfgh",
    "zxcvbn",
    "1qaz2wsx",
    "qazwsx",
)


@dataclass(frozen=True)
class PasswordReport:
    score: int
    rating: str
    entropy_bits: float
    passed_checks: tuple
    recommendations: tuple


def estimate_entropy(password):
    """Estimate password entropy using length and character variety."""
    pool_size = 0

    if re.search(r"[a-z]", password):
        pool_size += 26

    if re.search(r"[A-Z]", password):
        pool_size += 26

    if re.search(r"\d", password):
        pool_size += 10

    if re.search(r"[^A-Za-z0-9\s]", password):
        pool_size += 32

    if re.search(r"\s", password):
        pool_size += 1

    if not password or pool_size == 0:
        return 0.0

    return len(password) * math.log2(pool_size)


def contains_ordered_sequence(password, minimum_length=4):
    """Detect sequences such as abcd, dcba, 1234, or 4321."""
    password = password.lower()

    for pattern in ORDERED_PATTERNS:
        forward_pattern = pattern
        backward_pattern = pattern[::-1]

        for candidate in (forward_pattern, backward_pattern):
            for index in range(len(candidate) - minimum_length + 1):
                sequence = candidate[index:index + minimum_length]

                if sequence in password:
                    return True

    return False


def contains_keyboard_pattern(password):
    """Detect common keyboard patterns such as qwerty and asdfgh."""
    password = password.lower()

    for pattern in KEYBOARD_PATTERNS:
        if pattern in password or pattern[::-1] in password:
            return True

    return False


def analyze_password(password):
    """Analyze a password and return a detailed security report."""
    score = 0
    passed_checks = []
    recommendations = []

    # Check password length
    if len(password) >= 16:
        score += 30
        passed_checks.append("Excellent length: 16 or more characters")

    elif len(password) >= 12:
        score += 22
        passed_checks.append("Good length: 12 or more characters")

    elif len(password) >= 8:
        score += 10
        recommendations.append(
            "Increase the password to at least 12 characters."
        )

    else:
        recommendations.append("Use at least 12 characters.")

    # Check character variety
    character_rules = (
        (r"[a-z]", "lowercase letter"),
        (r"[A-Z]", "uppercase letter"),
        (r"\d", "number"),
        (r"[^A-Za-z0-9\s]", "special character"),
    )

    for pattern, label in character_rules:
        if re.search(pattern, password):
            score += 8
            passed_checks.append(f"Contains a {label}")

        else:
            recommendations.append(f"Add at least one {label}.")

    # Check character uniqueness
    if password:
        unique_characters = len(set(password))
        uniqueness_ratio = unique_characters / len(password)

        if uniqueness_ratio >= 0.70:
            score += 8
            passed_checks.append("Strong character variety")

        elif uniqueness_ratio < 0.45:
            recommendations.append(
                "Use a wider variety of characters."
            )

    # Estimate password entropy
    entropy = estimate_entropy(password)

    if entropy >= 75:
        score += 20
        passed_checks.append("High estimated entropy")

    elif entropy >= 50:
        score += 12
        passed_checks.append("Moderate estimated entropy")

    elif entropy >= 35:
        score += 5
        recommendations.append(
            "Add more length or variety to improve unpredictability."
        )

    else:
        recommendations.append("The password is too predictable.")

    lowered_password = password.lower()

    # Check for common passwords
    if lowered_password in COMMON_PASSWORDS:
        score -= 60
        recommendations.append(
            "Choose a unique password; this password is commonly used."
        )

    # Check for repeated characters
    if re.search(r"(.)\1{2,}", password):
        score -= 12
        recommendations.append(
            "Avoid repeating the same character three or more times."
        )

    # Check for predictable sequences
    if contains_ordered_sequence(password):
        score -= 12
        recommendations.append(
            "Avoid sequences such as 1234, 4321, abcd, or dcba."
        )

    # Check for keyboard patterns
    if contains_keyboard_pattern(password):
        score -= 12
        recommendations.append(
            "Avoid keyboard patterns such as qwerty or asdfgh."
        )

    # Check for years
    if re.search(r"(19|20)\d{2}", password):
        score -= 5
        recommendations.append(
            "Avoid easily guessed years or dates."
        )

    # Keep the score between 0 and 100
    score = max(0, min(round(score), 100))

    # Assign the final rating
    if score >= 80:
        rating = "STRONG"

    elif score >= 60:
        rating = "GOOD"

    elif score >= 40:
        rating = "MEDIUM"

    else:
        rating = "WEAK"

    # Remove duplicate recommendations
    recommendations = list(dict.fromkeys(recommendations))

    return PasswordReport(
        score=score,
        rating=rating,
        entropy_bits=round(entropy, 1),
        passed_checks=tuple(passed_checks),
        recommendations=tuple(recommendations),
    )


def display_report(report):
    """Display the results without revealing the password."""
    rating_symbols = {
        "STRONG": "✅",
        "GOOD": "🟢",
        "MEDIUM": "⚠️",
        "WEAK": "❌",
    }

    print("\nPASSWORD SECURITY REPORT")
    print("-" * 40)

    print(
        f"Strength: {report.rating} "
        f"{rating_symbols[report.rating]}"
    )

    print(f"Score: {report.score}/100")
    print(f"Estimated entropy: {report.entropy_bits} bits")

    if report.passed_checks:
        print("\nPassed checks:")

        for check in report.passed_checks:
            print(f"  ✅ {check}")

    if report.recommendations:
        print("\nRecommended improvements:")

        for recommendation in report.recommendations:
            print(f"  • {recommendation}")

    else:
        print("\nNo major weaknesses were detected.")

    print(
        "\nReminder: This score is an estimate. Use a unique password "
        "for every account and enable multi-factor authentication."
    )


def run_self_test():
    """Run tests to confirm that the analyzer works correctly."""
    test_cases = {
        "password": "WEAK",
        "abc123": "WEAK",
        "Blue-Coffee-River-92!": "STRONG",
    }

    for password, expected_rating in test_cases.items():
        actual_rating = analyze_password(password).rating

        assert actual_rating == expected_rating, (
            f"Expected {expected_rating}, but received "
            f"{actual_rating}."
        )

    print("All self-tests passed.")


def main():
    parser = argparse.ArgumentParser(
        description="Analyze password strength securely."
    )

    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run built-in tests instead of entering a password.",
    )

    args = parser.parse_args()

    if args.self_test:
        run_self_test()
        return

    print("PASSWORD STRENGTH ANALYZER")
    print("Your password will stay hidden while you type.")

    password = getpass("\nEnter your password: ")

    if not password:
        print("\nPassword cannot be empty.")
        return

    report = analyze_password(password)
    display_report(report)


if __name__ == "__main__":
    main()
