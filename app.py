from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv
import pyodbc
import os
import jwt
import requests
import struct

app = Flask(__name__)
CORS(app)

load_dotenv('.env')

driver = os.getenv('DRIVER')
server = os.getenv('SERVER')
database = os.getenv('DATABASE')
tenant_id = os.getenv('TENANT_ID')

def validate_and_get_sql_token(auth_header):
    """Validate the user's token and get a SQL database token"""
    if not auth_header or not auth_header.startswith('Bearer '):
        raise ValueError("Missing or invalid Authorization header")
    
    access_token = auth_header.split(' ')[1]
    
    decoded_token = jwt.decode(access_token, options={"verify_signature": False})
    user_principal_name = decoded_token.get('upn') or decoded_token.get('preferred_username')
    
    if not user_principal_name:
        raise ValueError("Could not extract user information from token")
    
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
        
        response = requests.post(token_url, data=data)
        
        if response.status_code != 200:
            return access_token, user_principal_name
        
        token_response = response.json()
        sql_token = token_response.get('access_token')
        
        return sql_token, user_principal_name
        
    except Exception as e:
        print(f"Token exchange failed: {e}")
        return access_token, user_principal_name

def get_connection_with_user_token(auth_header):
    """Create database connection using the user's token"""
    sql_token, user_name = validate_and_get_sql_token(auth_header)
    
    token_bytes = sql_token.encode("utf-16-le")
    token_struct = struct.pack(f'<I{len(token_bytes)}s', len(token_bytes), token_bytes)
    
    connection_string = f'DRIVER={driver};SERVER=tcp:{server},1433;DATABASE={database};Encrypt=yes;TrustServerCertificate=no;Connection Timeout=30;'
    
    conn = pyodbc.connect(connection_string, attrs_before={1256: token_struct})
    return conn, user_name

@app.route('/query', methods=['GET'])
def run_query():
    company_name = request.args.get('company')

    if not company_name:
        return jsonify({"error": "Missing 'company' query parameter"}), 400

    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({"error": "Missing Authorization header"}), 401

    try:
        with get_connection_with_user_token(auth_header)[0] as conn:
            cursor = conn.cursor()

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
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/user-info', methods=['GET'])
def get_user_info():
    """Get information about the authenticated user"""
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({"error": "Missing Authorization header"}), 401
    
    try:
        _, user_name = validate_and_get_sql_token(auth_header)
        return jsonify({"user": user_name, "authenticated": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 401
    
@app.route('/pulse', methods=['GET'])
def pulse():
    return jsonify('Alive!')

if __name__ == '__main__':
    app.run()