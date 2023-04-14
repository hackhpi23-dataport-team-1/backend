from flask import Flask, request, jsonify, make_response
from flask_cors import CORS, cross_origin
import uuid
import os
from werkzeug.utils import secure_filename
from xmlParser import parse
from enrich import *
import json
from score import update_score

app = Flask(__name__)
cors = CORS(app)

app.config['CORS_HEADERS'] = 'Content-Type'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'csv', 'xml'}
app.config['UPLOAD_FOLDER'] = 'uploads'

def _corsify_actual_response(response):
    return response

# def _build_cors_preflight_response():
#     response = make_response()
#     response.headers.add("Access-Control-Allow-Origin", "*")
#     response.headers.add("Access-Control-Allow-Headers", "*")
#     response.headers.add("Access-Control-Allow-Methods", "*")
#     return response

@app.route('/case', methods=['POST'])
@cross_origin()
def create():
  # if request.method == "OPTIONS": # CORS preflight
  #   return _build_cors_preflight_response()
  case_id = str(uuid.uuid4())
  app.logger.info('Case %s created', case_id)
  return _corsify_actual_response(jsonify({'case': case_id}))


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/case/<case_id>', methods=['POST'])
@cross_origin()
def upload(case_id):
  # if request.method == "OPTIONS": # CORS preflight
  #   return _build_cors_preflight_response()
  file = request.files['file']
  if file and allowed_file(file.filename):
    filename = secure_filename(file.filename)
    file.save(os.path.join(app.config['UPLOAD_FOLDER'], case_id + '_' + filename ))

    with open(os.path.join(app.config['UPLOAD_FOLDER'], case_id + '.txt'), 'a') as file:
      file.write(filename + '\n')
    return _corsify_actual_response(jsonify({'status': 200}))
    
  return _corsify_actual_response(jsonify({'status': 500}))

@app.route('/case/<case_id>', methods=['GET'])
@cross_origin()
def analyze(case_id):
  # get data with case_id
  url = os.path.join(app.config['UPLOAD_FOLDER'], case_id + '.txt' )
  with open(url, 'r') as f:
    data = f.read()

  filenames = data.split('\n')
  filenames = [x for x in filenames if x != '']
  
  for filename in filenames:
    with open(os.path.join(app.config['UPLOAD_FOLDER'], case_id + '_' + filename), 'r') as f:
      data = "exampleData/newEvent.xml"

  # analyze data
  graph = parse(data)

  # enrich
  # enriched_graph = enrich(graph)

  # TODO: get score
  # update_score(enriched_graph)

  # return graph in json format
  json_f = json.dumps(graph, default=lambda x: x.__dict__)

  return jsonify({'graph': json_f, 'data': data})

app.run()
