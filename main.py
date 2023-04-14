from flask import Flask, request, jsonify
from flask_cors import CORS, cross_origin
import uuid
import os
from werkzeug.utils import secure_filename
from xmlParser import parse
from enrich import *
import json

app = Flask(__name__)
cors = CORS(app)

app.config['CORS_HEADERS'] = 'Content-Type'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'csv', 'xml'}
app.config['UPLOAD_FOLDER'] = 'uploads'

@app.route('/case', methods=['POST'])
@cross_origin()
def create():
  case_id = str(uuid.uuid4())
  app.logger.info('Case %s created', case_id)
  return jsonify({'case': case_id})


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/case/<case_id>', methods=['POST'])
@cross_origin()
def upload(case_id):
  file = request.files['file']
  if file and allowed_file(file.filename):
    filename = secure_filename(file.filename)
    file.save(os.path.join(app.config['UPLOAD_FOLDER'], case_id + '_' + filename))
    return jsonify({'status': 200})
    
  return jsonify({'status': 500})

@app.route('/case/<case_id>', methods=['GET'])
@cross_origin()
def analyze(case_id):
  # get data with case_id
  with open('uploads/1_upload_test.txt', 'r') as f:
    data = f.read()
  
  # analyze data
  graph = parse(data)

  # enrich
  enriched_graph = enrich(graph)


  # TODO: get score

  # return graph in json format
  json_f = json.dumps(enriched_graph, default=lambda x: x.__dict__)

  return jsonify({'graph': json_f})

app.run()
