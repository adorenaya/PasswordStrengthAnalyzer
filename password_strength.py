import re  # Lets Python check letters, numbers, or symbols

def check_password_strength(password):
    score = 0  # Start with 0 points

    print("\nChecking password rules...\n")  # Shows that checks are starting

    # 1️⃣ Length
    if len(password) >= 8:
        print("✅ Length: Good (8+ characters)")
        score += 1
    else:
        print("❌ Length: Too short (minimum 8 characters)")

    # 2️⃣ Lowercase
    if re.search(r"[a-z]", password):
        print("✅ Lowercase: Found")
        score += 1
    else:
        print("❌ Lowercase: Missing")

    # 3️⃣ Uppercase
    if re.search(r"[A-Z]", password):
        print("✅ Uppercase: Found")
        score += 1
    else:
        print("❌ Uppercase: Missing")

    # 4️⃣ Numbers
    if re.search(r"\d", password):
        print("✅ Number: Found")
        score += 1
    else:
        print("❌ Number: Missing")

    # 5️⃣ Special characters
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        print("✅ Special character: Found")
        score += 1
    else:
        print("❌ Special character: Missing")

    # Final evaluation
    print("\nFinal Password Strength:")
    if score == 5:
        print("STRONG ✅")
    elif score >= 3:
        print("MEDIUM ⚠️")
    else:
        print("WEAK ❌")

# Ask the user for a password
password = input("Enter your password: ")

# Run the function
check_password_strength(password)

