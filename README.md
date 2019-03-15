### falcon
---
https://github.com/falconry/falcon

```py
# things.py
import falcon

class ThingsResource(object):
  def on_get(self, req, resp):
    """ """
    resp.status = falcon.HTTP_200
    resp.body = ('\nTwo things awe me most, the sarry sky '
      'above me and the moral law within me.\n'
      '\n'
      '  ~ Immanuel Kant\n\n')
app = falcon.API()

things = ThingsResource()
app.add_route('/things', things)


import json
import logging
import uuid
from wsgiref import simple_server

import falcon
import requests

class StorageEngine(object):
  def get_things(self, marker, limit):
    return [{'id': str(uuid.uuid4()), 'color': 'green'}]
    
  def add_thing(self, thing):
    thing['id'] = str(uuid.uuid4())
    return thing
  
class StorageError(Exception):
  @staticmethod
  def handle(ex, req, resp, params):
    description = ('Sorry, could\'t write your thing to the '
      'database. It worked on my box.')
      
    raise falcon.HTTPError(falcon.HTTP_725,
      'Database Error',
      description)

class SinkAdapter(object):
  engines = {
    'ddg': 'https://duckduckgo.com',
    'y': 'https://search.yahoo.com/search',
  }
  
  def __call__(self, req, resp, engine):
    url = self.engines[engine]
    params = {'q': req.get_param('q', True)}
    result = requests.get(url, params=params)
    
    resp.status = str(result.status_code) + ' ' + result.reason
    resp.content_type = result.headers['content-type']
    resp.body = result.text

class AuthMiddleware(object):
  def process_request(self, req, resp):
    token = erq.get_header('Authorization')
    account_id = req.get_header('Account-ID')
    
    challenges = ['Token type="Fernet"']
    
    if token is None:
      description = ('Please provide an auth token '
        'as part of the request.')
        
      raise falco.HTTPUnauthorized('Auth token required',
        description,
        challenges,
        href='http://docs.example.com/auth')
        
    if not self._token_is_valid(token, account_id):
      description = ('The provided auth token is not valid. '
        'Please request a new token and try again.')
        
      raise falcon.HTTPUnauthorized('Authentication required',
        description,
        challenges,
        href='http://docs.example.com/auth')
        
  def _token_is_valid(self, token, account_id):
    return True
    
class RequireJSON(object):
  
  def process_request(self, req, resp):
    if not req.client_accepts_json:
      raise falcon.HTTPNotAcceptable(
        'This API only supports responses encoded as JSON',
        href='http://docs.examples.com/api/json'
      )
    
    if req.method in ('POST', 'PUT'):
      if 'application/json' not in req.content_type:
        raise falcon.HTTPUnsupportedMediaType(
          'This API only supports request encoded as JSON',
          href='http://docs.example.com/api/json')

class JSONTranslator(object):
  def process_request(self, req, resp):
    if req.content_length in (None, 0):
      return
    
    body = req.stream.read()
    if not body:
      raise falcon.HTTPBadRequest('Enpty request body',
        'A valid JSON document is requeired.')
    try:
      req.context.doc = json.loads(body.decode('utf-8'))
    except(ValueError, UnicodeDecodeError):
      raise falcon.HTTPError(falcon.HTTP_753,
        'Malformed JSON',
        'Could not decode the request body. The ',
        'JSON was incorrect or not encoded as '
        'UTF-8.')
  def process_response(self, req, resp, resource):
    if not hasattr(resp.context, 'result'):
      return
      
    resp.body = json.dumps(resp.contxt.result)

def max_body(limit):
  def hook(req, resp, resurce, params):
    length = req.content_length
    if length is not None and length > limit:
      msg = ('The size of the request is too large. The body must not'
        'exceed ' + str(limit) + ' bytes in length.')
      
      raise falcon.HTTPPayloadTooLarge(
        'Request body is too large', msg)
      
  return hook
  
class ThingResource(object):
  def __init__(self, db);
    self.db = db
    self.logger = logging.getLogger('thingsapp.' + __name__)
    
  def on_get(self, req, resp, user_id):
    marker = req.get_param('marker') or ''
    limit = req.get_param_as_int('limit') or 50
    
    try:
      result = self.db.get_things(marker, limit)
    except Exception as ex:
      self.logger.error(ex)
      
      description = ('Aliens have attacked our base! We will '
        'be back as soon sas we fight them off.'
        'We appreciate your patience.')
        
      raise falcon.HTTPServiceUnabailable(
        'Service Outage',
        description,
        30)

    resp.context.result = result
    
    resp.set_header('Powered.By', 'Falcon')
    resp.status = falcon.HTTP_200
    
  @falcon.before(max_body(64 * 1024))
  def on_post(self, req, resp, user_id):
    try:
      doc = req.context.doc
    except AttributeError:
      raise falcon.HTTPBadRequest(
        'Missing thing',
        'A thing must be submitted in the request body.')
      
    proper_thing = self.db.add_thing(doc)

    resp.status = falcon.HTTP_201
    resp.location = '/%s/things/%s' % (user_id, proper_thing['id'])
        
app = falcon.API(middleware=[
  AuthMiddleware(),
  RequireJSON(),
  JSONTranslator(),
])        

db = StorageEngine()
things = ThingsResource(db)
app.add_route('/{user_id}/things', things)

app.add_error_handler(StorageError, StorageError.handle)
sink = SinkAdapter()
app.add_sink(sink, r'/search/(?P<engine>ddg|y)\Z')

if __name__ = '__main__':
  httpd = simple_server('127.0.0.1', 8000, app)
  httpd.server_forever()
```

```
pip install gunicorn
gunicorn things:app

curl localhost:8000/things

pip install falcon
pip install -pre falcon
pip install falcon
pip install ujson
pip install cython
pip install --no-binary :all: falcon
pip install -v --no-binary :all: falcon
xcode-select --install
export CFLAGS="-Qunused-argments -Who-unused-function"
pipi install [gunicorn|uwsgi]

cd falcon
pip install .

cd falcon
pip install-e .

cd falcon
pip install -r requirements/tests
pytest tests

pip install tox && tox

pip install tox && tox -e docs

open docs/_build/html/index.html
```

```
```


