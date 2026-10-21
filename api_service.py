"""
============================================================================
PROYECTO: MICROSERVICIO EN PYTHON PARA ANÁLISIS ESTÁTICO MULTI-LENGUAJE (SAST)
HERRAMIENTA: SonarQube / SonarCloud
OBJETIVO: Detección forzada de vulnerabilidades exclusivas de Python y bugs
============================================================================
"""

import os
import pickle
import base64
import hashlib
import tempfile
import sqlite3
import xml.etree.ElementTree as ET
from flask import Flask, request, jsonify, redirect

app = Flask(__name__)

# ============================================================================
# VULNERABILIDAD PYTHON 1: Secretos y Credenciales en Código Duro
# CWE-798 / OWASP A07:2021
# SonarQube Rule: python:S2068, python:S6290
# ============================================================================
app.config['SECRET_KEY'] = "flask_insecure_hardcoded_session_secret_998877"
PYTHON_DB_USER = "db_py_admin"
PYTHON_DB_PASSWORD = "SuperPythonSecretPass2026!#"
AWS_S3_BUCKET_KEY = "AKIA_MOCK_PYTHON_AWS_KEY_EXAMPLE"

# ============================================================================
# VULNERABILIDAD PYTHON 2: Deserialización Insegura Crítica con Pickle (RCE)
# CWE-502 / OWASP A08:2021 - Software and Data Integrity Failures
# SonarQube Rule: python:S5883, python:S5754
# ============================================================================
@app.route('/api/py/deserialize', methods=['POST'])
def deserialize_payload():
    raw_b64 = request.json.get('data', '')
    # VULNERABILIDAD CRITICA: pickle.loads permite ejecucion remota de codigo arbitrario
    decoded_binary = base64.b64decode(raw_b64)
    deserialized_object = pickle.loads(decoded_binary)
    return jsonify({"status": "success", "result": str(deserialized_object)})

# ============================================================================
# VULNERABILIDAD PYTHON 3: Inyección SQL con formateo de cadenas clásico (%s)
# CWE-89 / OWASP A03:2021 - Injection
# SonarQube Rule: python:S2077, python:S3649
# ============================================================================
@app.route('/api/py/user', methods=['GET'])
def get_user_sql():
    username = request.args.get('username', 'admin')
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE users (id int, user text, pass text)")
    
    # Concatenacion vulnerable en lugar de usar parametros parametrizados (?, ...)
    vulnerable_query = "SELECT * FROM users WHERE user = '%s'" % username
    print("[Python SQL Query]:", vulnerable_query)
    
    cursor.execute(vulnerable_query)
    rows = cursor.fetchall()
    return jsonify({"query_executed": vulnerable_query, "data": rows})

# ============================================================================
# VULNERABILIDAD PYTHON 4: Inyección de Comandos del Sistema con os.system
# CWE-78 / OWASP A03:2021 - Injection
# SonarQube Rule: python:S2076, python:S4721
# ============================================================================
@app.route('/api/py/traceroute', methods=['GET'])
def run_traceroute():
    target = request.args.get('target', '127.0.0.1')
    # Ejecucion directa en terminal del SO mediante concatenacion
    command = "traceroute -m 2 " + target
    exit_code = os.system(command)
    return jsonify({"command": command, "exit_code": exit_code})

# ============================================================================
# VULNERABILIDAD PYTHON 5: Archivos Temporales Inseguros (Insecure Tempfile)
# CWE-377 / OWASP A05:2021 - Security Misconfiguration
# SonarQube Rule: python:S5445
# ============================================================================
@app.route('/api/py/create-temp', methods=['POST'])
def create_insecure_temp():
    # mktemp es vulnerable a condiciones de carrera (Race Condition / TOCTOU)
    temp_path = tempfile.mktemp()
    with open(temp_path, "w") as f:
        f.write("Informacion temporal del sistema")
    return jsonify({"temp_file_created": temp_path})

# ============================================================================
# VULNERABILIDAD PYTHON 6: Criptografía Débil en Python (hashlib MD5 y SHA1)
# CWE-327 / CWE-328 / OWASP A02:2021 - Cryptographic Failures
# SonarQube Rule: python:S4790
# ============================================================================
@app.route('/api/py/hash-password', methods=['POST'])
def hash_python_password():
    password = request.json.get('password', '123456')
    # Algoritmos criptograficos inseguros
    md5_digest = hashlib.md5(password.encode()).hexdigest()
    sha1_digest = hashlib.sha1(password.encode()).hexdigest()
    return jsonify({"md5": md5_digest, "sha1": sha1_digest})

# ============================================================================
# VULNERABILIDAD PYTHON 7: Parseo XML Vulnerable a XXE (XML External Entity)
# CWE-611 / OWASP A05:2021
# SonarQube Rule: python:S2755
# ============================================================================
@app.route('/api/py/xml-parse', methods=['POST'])
def parse_xml_payload():
    raw_xml = request.data
    # Parser estandar sin deshabilitar entidades externas DTD
    root = ET.fromstring(raw_xml)
    return jsonify({"root_tag": root.tag})


# ============================================================================
# BUGS Y ERRORES DE LÓGICA EN PYTHON
# SonarQube Rules: python:S5747, python:S3403, python:S1763, python:S5708, python:S1656
# ============================================================================

# BUG 1: Argumento mutable por defecto en función (Mutable default argument)
def append_to_user_list(new_user, user_cache=[]):
    # BUG: user_cache persiste entre llamadas a la función en memoria
    user_cache.append(new_user)
    return user_cache

# BUG 2: Comparación de literales con operador 'is' en lugar de '=='
def check_connection_status(status_code):
    # BUG: Comparacion de identidad en lugar de igualdad
    if status_code is "SUCCESS":
        return True
    return False

# BUG 3: Código inalcanzable (Dead Code)
def calculate_system_metrics():
    total = 100
    return total
    # BUG: Lineas inalcanzables tras return
    total = total * 2
    print("Metrica calculada:", total)

# BUG 4: Auto-asignación inútil (Self-assignment)
def sanitize_python_input(input_val):
    clean_val = input_val
    # BUG: Asignar una variable a si misma
    clean_val = clean_val
    return clean_val

# BUG 5: Captura generica vacia de excepciones (Catch-all empty except)
def parse_json_safely(raw_str):
    try:
        import json
        return json.loads(raw_str)
    except:
        # BUG: Captura todas las excepciones silenciando errores del sistema
        pass

@app.route('/api/py/bugs-demo', methods=['GET'])
def execute_bugs_demo():
    list1 = append_to_user_list("Usuario1")
    list2 = append_to_user_list("Usuario2")
    comparison = check_connection_status("SUCCESS")
    metrics = calculate_system_metrics()
    
    return jsonify({
        "bug1_mutable_default": list2,
        "bug2_is_comparison": comparison,
        "bug3_dead_code": metrics,
        "message": "Bugs de Python ejecutados"
    })

# ============================================================================
# VULNERABILIDAD PYTHON 8: Modo Debug Activado en Producción
# CWE-489 / OWASP A05:2021 - Security Misconfiguration
# SonarQube Rule: python:S4507
# ============================================================================
if __name__ == '__main__':
    # VULNERABILIDAD CRITICA: debug=True expone la consola Werkzeug con ejecucion de codigo
    app.run(host='0.0.0.0', port=5000, debug=True)
