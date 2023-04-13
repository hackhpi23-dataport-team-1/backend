from flask import Flask, request, jsonify
from flask_cors import CORS, cross_origin
import uuid

app = Flask(__name__)
cors = CORS(app)

app.config['CORS_HEADERS'] = 'Content-Type'

@app.route('/case', methods=['POST'])
@cross_origin()
def create():
  case_id = str(uuid.uuid4())
  app.logger.info('Case %s created', case_id)
  return jsonify({'case': case_id})

@app.route('/case/<case_id>', methods=['POST'])
@cross_origin()
def upload(case_id):
  return jsonify({'ok': True})

@app.route('/case/<case_id>', methods=['GET'])
@cross_origin()
def analyze(case_id):
  return jsonify({
    'vertices': [{
        'id': 'BCC8A2AC-8850-4C79-88AD-F0B7AD3BDA2B',
        'kind': 'process',
        'score': 100,
        'attrs': {
          'image': '/sbin/sudo'
        }
      },
      {
        'id': 'E0A31FDA-6FC9-4A88-9392-949171C84750',
        'kind': 'ip',
        'score': 80,
        'attrs': {
          'value': '1.1.1.1'
        }
      },
      {
        'id': 'AB384E5A-FD88-4EB5-B0C7-69AA7047E99E',
        'kind': 'as',
        'score': 20,
        'attrs': {
          'asn': 13335
        }
    }],
    'edges': [{
      'from': 'BCC8A2AC-8850-4C79-88AD-F0B7AD3BDA2B',
      'to': 'E0A31FDA-6FC9-4A88-9392-949171C84750',
      'kind': 'udp-connect',
      'attrs': {
        'port': 53
      }
    }, {
      'from': 'E0A31FDA-6FC9-4A88-9392-949171C84750',
      'to': 'AB384E5A-FD88-4EB5-B0C7-69AA7047E99E',
      'kind': 'owned-by',
      'attrs': {
        'netname': 'APNIC-LABS',
        'subnet': '1.1.1.1/24'
      }
    }],
    'groups': [{
      'kind': 'host',
      'label': 'L-123-123',
      'vertices': ['BCC8A2AC-8850-4C79-88AD-F0B7AD3BDA2B'],
      'attrs': {
        'hostname': 'L-123-123',
        'ethers': ['9e:09:0e:db:99:6e', '9e:09:0e:db:99:6a']
      }
    }]
  })

app.run()
