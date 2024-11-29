import json
from flask import Flask, request, jsonify
import requests
from datetime import datetime
from cryptography.fernet import Fernet
from functools import wraps
import logging
import django
from django.conf import settings
from django.db import models
from django.core.management import execute_from_command_line

# Django setup
settings.configure(
    INSTALLED_APPS=[
        'django.contrib.contenttypes',
        'django.contrib.auth',
        'django.contrib.sessions',
        'django.contrib.messages',
    ],
    DATABASES={
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': 'db.sqlite3',
        }
    }
)
django.setup()

# Django models
class User(models.Model):
    username = models.CharField(max_length=50, unique=True)
    account_number = models.CharField(max_length=20)
    balance = models.DecimalField(max_digits=20, decimal_places=2)
    password = models.CharField(max_length=100)
    name = models.CharField(max_length=100)
    address = models.CharField(max_length=255)
    dob = models.DateField()
    id_number = models.CharField(max_length=20)

class Transaction(models.Model):
    sender = models.ForeignKey(User, related_name='sent_transactions', on_delete=models.CASCADE)
    receiver_account = models.CharField(max_length=20)
    amount = models.DecimalField(max_digits=20, decimal_places=2)
    reason = models.CharField(max_length=255)
    timestamp = models.DateTimeField(auto_now_add=True)

# Generate a key for encryption - store securely in a real application
key = Fernet.generate_key()
cipher = Fernet(key)

# Server-Side Code
try:
    from flask import Flask, request, jsonify
except ModuleNotFoundError:
    import subprocess
    subprocess.check_call(['pip', 'install', 'flask'])
    from flask import Flask, request, jsonify

app = Flask(__name__)

# Configure logging for audit trails
logging.basicConfig(filename='transaction_logs.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Authentication decorator
def authenticate(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth = request.authorization
        if not auth or not verify_user(auth.username, auth.password):
            logging.warning(f"Authentication failed for user: {auth.username if auth else 'Unknown'}")
            return jsonify({'status': 'failure', 'message': 'Authentication required'}), 401
        logging.info(f"User {auth.username} authenticated successfully")
        return f(*args, **kwargs)
    return decorated_function

def verify_user(username, password):
    try:
        user = User.objects.get(username=username)
        if user and user.password == password:
            return True
    except User.DoesNotExist:
        pass
    return False

# KYC Verification function
def verify_kyc(username):
    try:
        user = User.objects.get(username=username)
        if user.name and user.address and user.dob and user.id_number:
            logging.info(f"KYC verification successful for user: {username}")
            return True
        else:
            logging.warning(f"KYC verification failed for user: {username} - Incomplete KYC information")
    except User.DoesNotExist:
        logging.warning(f"KYC verification failed for user: {username} - User does not exist")
    return False

# Endpoint to initiate wire transfer
@app.route('/wire_transfer', methods=['POST'])
@authenticate
def wire_transfer():
    try:
        # Extract data from the request
        data = request.get_json()
        sender = request.authorization.username
        receiver_account = data['receiver_account']
        amount = data['amount']
        reason = data['reason']

        # Verify KYC
        if not verify_kyc(sender):
            logging.error(f"Wire transfer failed for user {sender}: KYC verification failed")
            return jsonify({'status': 'failure', 'message': 'KYC verification failed'}), 403

        # Verify sender exists and has sufficient funds
        try:
            user = User.objects.get(username=sender)
            if user.balance < amount:
                logging.error(f"Wire transfer failed for user {sender}: Insufficient funds")
                return jsonify({'status': 'failure', 'message': 'Insufficient funds'}), 400
        except User.DoesNotExist:
            logging.error(f"Wire transfer failed for user {sender}: Invalid user")
            return jsonify({'status': 'failure', 'message': 'Invalid user'}), 400

        # Compliance Checks (simplified KYC/AML checks)
        if amount >= 3000:  # Threshold for recordkeeping as per FFIEC guidelines
            log_aml_compliance(sender, receiver_account, amount)

        # Perform AML checks for suspicious activity
        if is_suspicious_activity(sender, receiver_account, amount):
            logging.error(f"Transaction flagged for AML compliance review: {sender} to {receiver_account} for amount ${amount}")
            return jsonify({'status': 'failure', 'message': 'Transaction flagged for AML compliance review'}), 403

        # Deduct amount from sender's account
        user.balance -= amount
        user.save()

        # Record the transaction
        transaction = Transaction.objects.create(
            sender=user,
            receiver_account=receiver_account,
            amount=amount,
            reason=reason
        )

        # Encrypt transaction details (for secure storage)
        encrypted_transaction = cipher.encrypt(json.dumps({
            'sender': sender,
            'receiver_account': receiver_account,
            'amount': float(amount),
            'reason': reason,
            'timestamp': transaction.timestamp.isoformat()
        }).encode())

        # Log the transaction for audit trail
        logging.info(f"Transaction successful: {transaction}")

        # In a real application, store encrypted_transaction in a secure database
        return jsonify({'status': 'success', 'transaction': encrypted_transaction.decode()}), 200

    except Exception as e:
        logging.error(f"Error processing wire transfer: {str(e)}")
        return jsonify({'status': 'failure', 'message': str(e)}), 500

# Function to log large transactions for AML compliance
def log_aml_compliance(sender, receiver_account, amount):
    # Placeholder for AML logging - in reality, this would report to federal authorities
    logging.warning(f"AML Alert: Large transaction detected from {sender} to {receiver_account} of amount ${amount}")

# Function to check for suspicious activity for AML compliance
def is_suspicious_activity(sender, receiver_account, amount):
    # Placeholder for AML suspicious activity detection
    # In reality, use machine learning models or rule-based checks to detect suspicious patterns
    # Example: Flag transactions to high-risk countries or rapid multiple transactions
    suspicious_patterns = [
        lambda s, r, a: a > 5000 and r == "high-risk-account",
        lambda s, r, a: len([t for t in Transaction.objects.filter(sender__username=s)]) > 3
    ]
    
    for pattern in suspicious_patterns:
        if pattern(sender, receiver_account, amount):
            logging.warning(f"AML Alert: Suspicious activity detected for transaction from {sender} to {receiver_account} of amount ${amount}")
            return True
    return False

if __name__ == '__main__':
    execute_from_command_line(['manage.py', 'migrate'])
    app.run(debug=True, port=5000)

# Client-Side Code
def initiate_wire_transfer(sender, password, receiver_account, amount, reason):
    url = 'http://127.0.0.1:5000/wire_transfer'
    headers = {'Content-Type': 'application/json'}
    payload = {
        'receiver_account': receiver_account,
        'amount': amount,
        'reason': reason
    }
    try:
        response = requests.post(url, headers=headers, json=payload, auth=(sender, password))
        if response.status_code == 200:
            logging.info(f"Client: Transfer successful for user {sender} to {receiver_account} of amount ${amount}")
            print('Transfer successful:', response.json())
        else:
            logging.error(f"Client: Transfer failed for user {sender} to {receiver_account} of amount ${amount}: {response.json()}")
            print('Transfer failed:', response.json())
    except requests.exceptions.RequestException as e:
        logging.error(f"Client: Error initiating transfer for user {sender}: {str(e)}")
        print('Error initiating transfer:', e)

# Example Usage (Client-Side)
if __name__ == "__main__":
    # Example wire transfer from client
    initiate_wire_transfer('user1', 'securepassword', '987654321', 2000, 'Payment for services')

