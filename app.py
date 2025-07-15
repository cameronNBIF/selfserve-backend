from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv
import pyodbc
import os
import jwt
import requests
import struct
import time
from functools import wraps

app = Flask(__name__)
CORS(app)

load_dotenv('.env')

driver = os.getenv('DRIVER')
server = os.getenv('SERVER')
database = os.getenv('DATABASE')
tenant_id = os.getenv('TENANT_ID')

class TokenExpiredError(Exception):
    """Custom exception for expired tokens"""
    pass

class DatabaseConnectionError(Exception):
    """Custom exception for database connection issues"""
    pass

def validate_and_get_sql_token(auth_header):
    """Validate the user's token and get a SQL database token"""
    if not auth_header or not auth_header.startswith('Bearer '):
        raise ValueError("Missing or invalid Authorization header")
    
    access_token = auth_header.split(' ')[1]
    
    # Check if token is expired
    try:
        decoded_token = jwt.decode(access_token, options={"verify_signature": False})
        exp = decoded_token.get('exp')
        if exp and time.time() > exp:
            raise TokenExpiredError("Token has expired")
            
        user_principal_name = decoded_token.get('upn') or decoded_token.get('preferred_username')
        
        if not user_principal_name:
            raise ValueError("Could not extract user information from token")
    except jwt.DecodeError:
        raise ValueError("Invalid token format")
    
    try:
        token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
        
        data = {
            'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
            'client_id': os.getenv('CLIENT_ID'),
            'client_secret': os.getenv('CLIENT_SECRET'),
            'assertion': access_token,
            'scope': 'https://database.windows.net/.default',
            'requested_token_use': 'on_behalf_of'
        }
        
        response = requests.post(token_url, data=data, timeout=10)
        
        if response.status_code == 400:
            error_data = response.json()
            if 'AADSTS700082' in str(error_data) or 'expired' in str(error_data).lower():
                raise TokenExpiredError("Token has expired")
        
        if response.status_code != 200:
            print(f"Token exchange failed with status {response.status_code}: {response.text}")
            return access_token, user_principal_name
        
        token_response = response.json()
        sql_token = token_response.get('access_token')
        
        return sql_token, user_principal_name
        
    except requests.RequestException as e:
        print(f"Token exchange request failed: {e}")
        return access_token, user_principal_name
    except Exception as e:
        print(f"Token exchange failed: {e}")
        return access_token, user_principal_name

def get_connection_with_user_token(auth_header):
    sql_token, user_name = validate_and_get_sql_token(auth_header)
    
    token_bytes = sql_token.encode("utf-16-le")
    token_struct = struct.pack(f'<I{len(token_bytes)}s', len(token_bytes), token_bytes)
    
    connection_string = f'DRIVER={driver};SERVER=tcp:{server},1433;DATABASE={database};Encrypt=yes;TrustServerCertificate=no;Connection Timeout=30;'
    
    try:
        conn = pyodbc.connect(connection_string, attrs_before={1256: token_struct})
        return conn, user_name
    except pyodbc.Error as e:
        error_code = e.args[0] if e.args else None
        if error_code == 'HYT00':
            raise DatabaseConnectionError("Database connection timeout")
        elif error_code == '28000':
            raise TokenExpiredError("Database authentication failed - token may be expired")
        else:
            raise DatabaseConnectionError(f"Database connection failed: {str(e)}")

def handle_auth_errors(f):
    """Decorator to handle authentication and database errors"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except TokenExpiredError:
            return jsonify({
                "error": "Token expired",
                "error_type": "TOKEN_EXPIRED",
                "message": "Your session has expired. Please log in again."
            }), 401
        except DatabaseConnectionError as e:
            return jsonify({
                "error": str(e),
                "error_type": "DATABASE_CONNECTION_ERROR",
                "message": "Unable to connect to the database. Please try again."
            }), 503
        except ValueError as e:
            return jsonify({
                "error": str(e),
                "error_type": "VALIDATION_ERROR"
            }), 400
        except Exception as e:
            return jsonify({
                "error": str(e),
                "error_type": "INTERNAL_ERROR"
            }), 500
    return decorated_function

@app.route('/query', methods=['GET'])
@handle_auth_errors
def run_query():
    company_name = request.args.get('company')

    if not company_name:
        return jsonify({"error": "Missing 'company' query parameter"}), 400

    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({"error": "Missing Authorization header"}), 401

    max_retries = 2
    retry_delay = 1
    
    for attempt in range(max_retries + 1):
        try:
            with get_connection_with_user_token(auth_header)[0] as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT 1")  # Test connection
                cursor.fetchone()

                query = """
                    SELECT * 
                    FROM Investment 
                    LEFT JOIN (
                        VoucherCompany 
                        LEFT JOIN CompanyAsgmt ON VoucherCompany.CompanyID = CompanyAsgmt.CompanyID
                    ) ON Investment.RefNum = CompanyAsgmt.RefNum
                    WHERE CompanyName LIKE ?
                """
                param = f"%{company_name}%"
                cursor.execute(query, (param,))

                columns = [column[0] for column in cursor.description]
                results = [dict(zip(columns, row)) for row in cursor.fetchall()]

            return jsonify(results)
            
        except (DatabaseConnectionError, pyodbc.Error) as e:
            if attempt < max_retries:
                print(f"Attempt {attempt + 1} failed: {e}. Retrying in {retry_delay} seconds...")
                time.sleep(retry_delay)
                retry_delay *= 2
                continue
            else:
                raise DatabaseConnectionError("Database connection failed after multiple attempts")

@app.route('/user-info', methods=['GET'])
@handle_auth_errors
def get_user_info():
    """Get information about the authenticated user"""
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({"error": "Missing Authorization header"}), 401
    
    _, user_name = validate_and_get_sql_token(auth_header)
    return jsonify({"user": user_name, "authenticated": True})
    
@app.route('/pulse', methods=['GET'])
def pulse():
    return jsonify('Alive!')

if __name__ == '__main__':
    app.run()