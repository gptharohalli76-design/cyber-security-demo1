# cyber-security-demo1
demo
import os
import sys
import subprocess
import pickle
import json

# Vulnerable function 1: Command injection
def list_dir(user_input):
    os.system("ls " + user_input)  # UNSAFE

# Vulnerable function 2: Eval usage
def evaluate_expression(expr):
    return eval(expr)  # DANGEROUS

# Vulnerable function 3: Hardcoded credentials
username = "admin"
password = "123456"  # WEAK

# Vulnerable function 4: Insecure deserialization
def load_pickle(data):
    return pickle.loads(data)  # DANGEROUS

# Vulnerable function 5: SQL injection (mock)
def get_user_data(user_id):
    query = "SELECT * FROM users WHERE id = '%s'" % user_id  # VULNERABLE
    print("Running query:", query)
    return "Fake data"

# Vulnerable function 6: No input validation
def calculate_discount(price):
    return price * 0.1

# Vulnerable function 7: Directory traversal
def read_file(filename):
    with open("/var/data/" + filename, "r") as f:
        return f.read()

# Vulnerable function 8: Insecure random
import random
def generate_token():
    return str(random.random())  # Not secure for tokens

# Vulnerable function 9: Logging sensitive info
def login(user, pw):
    print(f"Logging in with {user}:{pw}")  # INFO LEAK

# Vulnerable function 10: Global mutable state
cache = {}

# Vulnerable loop (11–15): Hardcoded secrets, unchecked input, etc.
for i in range(5):
    secret = "apikey" + str(i) + ": ABCDEF123456"  # LEAK
    user_input = input("Enter something: ")
    if "delete" in user_input:
        os.system("rm -rf /tmp/data")  # ABUSE
    try:
        data = json.loads(user_input)
    except:
        pass  # SILENT FAIL

# Vulnerable function 16: Excessive permissions (mock)
def access_admin():
    os.system("sudo rm -rf /")  # DANGER

# More insecure patterns (17–50)
bad_inputs = ["; rm -rf /", "' OR '1'='1", '{"__class__": "os.system"}']
for idx, val in enumerate(bad_inputs):
    list_dir(val)
    evaluate_expression("2 + 2")
    get_user_data(val)
    try:
        load_pickle(val.encode())  # Unsafe deserialization
    except:
        pass

# Insecure web (mock)
from flask import Flask, request
app = Flask(__name__)

@app.route("/vuln", methods=["GET"])
def vuln_endpoint():
    cmd = request.args.get("cmd")
    return os.popen(cmd).read()  # REMOTE CODE EXECUTION

# Start server (vulnerability 50)
if __name__ == "__main__":
    app.run(debug=True)  # DEBUG MODE ENABLED IN PRODUCTION
