questions = [
    {
        "question": "You receive an email asking for your bank password. What should you do?",
        "options": ["A. Share it", "B. Ignore and report it", "C. Reply to the email"],
        "answer": "B"
    },
    {
        "question": "Which of the following is a sign of a phishing email?",
        "options": ["A. Poor grammar", "B. Suspicious links", "C. Both A and B"],
        "answer": "C"
    },
    {
        "question": "Should you click links from unknown senders?",
        "options": ["A. Yes", "B. No"],
        "answer": "B"
    },
    {
        "question": "What is phishing?",
        "options": [
            "A. A cyberattack used to steal information",
            "B. A programming language",
            "C. A computer game"
        ],
        "answer": "A"
    },
    {
        "question": "What should you check before clicking a link?",
        "options": [
            "A. URL destination",
            "B. Sender identity",
            "C. Both A and B"
        ],
        "answer": "C"
    }
]

score = 0

print("\n=== Phishing Awareness Training Quiz ===\n")

for i, q in enumerate(questions, start=1):
    print(f"Question {i}: {q['question']}")

    for option in q["options"]:
        print(option)

    user_answer = input("Your Answer: ").upper()

    if user_answer == q["answer"]:
        print("Correct!\n")
        score += 1
    else:
        print(f"Wrong! Correct answer is {q['answer']}\n")

print("=" * 40)
print(f"Final Score: {score}/{len(questions)}")

percentage = (score / len(questions)) * 100

if percentage >= 80:
    print("Excellent! You understand phishing risks.")
elif percentage >= 50:
    print("Good effort. Review phishing awareness practices.")
else:
    print("You need more phishing awareness training.")

print("=" * 40)