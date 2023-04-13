from flask import Flask, request, jsonify
import uuid

app = Flask(__name__)

@app.route('/case', methods=['POST'])
def create():
  case_id = str(uuid.uuid4())
  app.logger.info('Case %s created', case_id)
  return jsonify({'ok': True, 'case': case_id})

@app.route('/case/<case_id>', methods=['POST'])
def upload(case_id):
  return jsonify({'ok': True})

@app.route('/case/<case_id>', methods=['GET'])
def analyze(case_id):
  return jsonify({})

app.run()
