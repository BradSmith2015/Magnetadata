#server.py
import os
import flask
import request

import google.oauth2.credentials
from google.oauth2 import id_token
import google_auth_oauthlib.flow
import googleapiclient.discovery

CLIENT_SECRETS_FILE = 'client_secert.json'
SCOPES = ['https://www.googleapis.com/auth/yt-analytics.readonly']

API_SERVICE_NAME = 'youtubeAnalytics'
API_VERSION = 'v2'

app = flask.Flask(__name__)

app.secret_key = '111111111111111111111111111111111111111111111111'

@app.route('/')
def index():
    return print_index()

@app.route('/test')
def test_api_request():
    if 'credentials' not in flask.session:
        return flask.redirect('yo')
    credentials = google.oauth2.credentials.Credentials(
      **flask.session['credentials'])
    youtube = googleapiclient.discovery.build(
      API_SERVICE_NAME, API_VERSION, credentials=credentials)
    results=youtube.reports().query(ids='channel==MINE',
    startDate = '2014-06-01',
    endDate = '2018-06-01',
    dimensions="ageGroup,gender",
    metrics="viewerPercentage",
    filters="country==US",
    sort="gender,ageGroup").execute()
    flask.session['credentials'] = credentials_to_dict(credentials)
    return flask.jsonify(**results)

@app.route('/yo')
def authorize():
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
      CLIENT_SECRETS_FILE, scopes=SCOPES)
    flow.redirect_uri =  flask.url_for('oauth2callback', _external=True)
    authorization_url,state = flow.authorization_url(
    # Enable offline access so that you can refresh an access token without
    # re-prompting the user for permission. Recommended for web server apps.
    access_type='offline',
    # Enable incremental authorization. Recommended as a best practice.
    include_granted_scopes='true')
    flask.session['state'] = state
    return flask.redirect(authorization_url)
@app.route('/hello')
def oauth2callback():
    state = flask.session['state']
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
      CLIENT_SECRETS_FILE, scopes=SCOPES, state=state)
    flow.redirect_uri = flask.url_for('oauth2callback', _external=True)

    authorization_response = flask.request.url
    flow.fetch_token(authorization_response=authorization_response)
     #Store credentials in the session.
  # ACTION ITEM: In a production app, you likely want to save these
  #              credentials in a persistent database instead.
    credentials = flow.credentials
    flask.session['credentials'] = credentials_to_dict(credentials)

    return flask.redirect(flask.url_for('test_api_request'))

def credentials_to_dict(credentials):
  return {'token': credentials.token,
          'refresh_token': credentials.refresh_token,
          'token_uri': credentials.token_uri,
          'client_id': credentials.client_id,
          'client_secret': credentials.client_secret,
          'scopes': credentials.scopes}


def print_index():
    return '<a href="/yo">Test that shit</a>'

if __name__ == '__main__':
  # When running locally, disable OAuthlib's HTTPs verification.
  # ACTION ITEM for developers:
  #     When running in production *do not* leave this option enabled.
  os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
  os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'

  # Specify a hostname and port that are set as a valid redirect URI
  # for your API project in the Google API Console.
  app.run('localhost', 8080, debug=True)
















"""from flask import Flask, render_template, redirect
from GoogleOAuthoSetup import *

app = Flask(__name__, static_folder="../static/dist",
template_folder="../static")

@app.route("/")
def index():
    return redirect(authorization_url)
@app.route("/hello")
def hello():

    return "Hello World!"

if __name__ == "__main__":
    app.run()
"""
