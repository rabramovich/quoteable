# !/usr/bin/env python

from flask import Flask, render_template, request, redirect
from flask import jsonify, url_for, flash
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Source, Quote, User
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

app = Flask(__name__)

CLIENT_ID = json.loads(open('client_secrets.json', 'r').read())['web'][
        'client_id']
APPLICATION_NAME = "quoteable"


# Modify connection based on information found in this thread:
# https://hub.udacity.com/rooms/community:nd004-ent:692347-project-5/
#       community:thread-10709048535-1439193?contextType=room
#
# Connect to Database and create database session
engine = create_engine('sqlite:///quotes.db',
                       connect_args={'check_same_thread': False})
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# Create anti-forgery state token
@app.route('/login')
def showLogin():
    """Creates state token for login_session"""
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    """Authenticates with OAuth2 to Google sign-in"""
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps(
                        'Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    # ADD PROVIDER TO LOGIN SESSION
    login_session['provider'] = 'google'

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(login_session["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 200px; height: 200px;border-radius: 150px;'
    output += '-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output


# User Helper Functions
def createUser(login_session):
    """Creates user object in database from login_session object"""
    newUser = User(
        name=login_session['username'],
        email=login_session['email'],
        picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    """ Returns User object for selected user_id"""
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    """ Returns User object for selected email address"""
    user = session.query(User).filter_by(email=email).one()
    return user.id


# DISCONNECT - Revoke a current user's token and reset their login_session
# some items moved from main disconnect module since only one login provider.
@app.route('/gdisconnect')
def gdisconnect():
    """Disconnect user from Google Sign-in"""
    # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
                json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = ('https://accounts.google.com/o/oauth2/revoke?token=%s'
           % login_session['access_token'])
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps(
            'Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


# JSON APIs to view all Quotes for a Source
@app.route('/source/<int:source_id>/quote/JSON')
def sourceQuoteJSON(source_id):
    """Show all quotes by selected author (Source)"""
    source = session.query(Source).filter_by(id=source_id).one()
    items = session.query(Quote).filter_by(
        source_id=source_id).all()
    return jsonify(quote=[i.serialize for i in items])


@app.route('/source/<int:source_id>/quote/<int:quote_id>/JSON')
def quoteJSON(source_id, quote_id):
    """Show selected quote by selected Author (Source)"""
    quote = session.query(Quote).filter_by(id=quote_id).one()
    return jsonify(quote=quote.serialize)


@app.route('/source/JSON')
def sourcesJSON():
    """Show Author (Source) List in JSON Format"""
    sources = session.query(Source).all()
    return jsonify(source=[r.serialize for r in sources])


# Show all Sources
@app.route('/')
@app.route('/source/')
def showSources():
    """Show all the current sources (authors) in the database"""
    sources = session.query(Source).order_by(asc(Source.name))
    if 'username' not in login_session:
        return render_template('publicsources.html', sources=sources)
    else:
        return render_template('sources.html', sources=sources)


def checkInput(i, min=1, max=250):
    """ Check for valid input length based on database restrictions"""

    if min <= len(i) <= max:
        return True
    else:
        return False


# Create a new source
# added validation of input.
@app.route('/source/new/', methods=['GET', 'POST'])
def newSource():
    """ Create a new source (author)"""
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        newSource = Source(
            name=request.form['name'], user_id=login_session['user_id'])
        if checkInput(newSource.name):
            session.add(newSource)
            flash('New Author %s Successfully Created' % newSource.name)
            session.commit()
            return redirect(url_for('showSources'))
        else:
            flash('Invalid input. Enter input less than 250 char.')
            return redirect(url_for('showSources'))
    else:
        return render_template('newSource.html')


# Edit a source
# added session.commit so edits are commited into the database.
# added validation of input
@app.route('/source/<int:source_id>/edit/', methods=['GET', 'POST'])
def editSource(source_id):
    """ Edit the source (author)"""
    originalSource = session.query(
        Source).filter_by(id=source_id).one()
    if 'username' not in login_session:
        return redirect('/login')
    if originalSource.user_id != login_session['user_id']:
        return """<script>function myFunction() {alert(
        'You are not authorized to edit this author. Please create your own
        author in order to edit.');}</script><body onload='myFunction()'>"""
    if request.method == 'POST':
        if checkInput(request.form['name']):
            originalSource.name = request.form['name']
            flash('Author successfully edited %s' % editedSource)
            session.commit()
            return redirect(url_for('showSources'))
        else:
            flash('Invalid input or input more than 250 char.')
            return redirect(url_for('showSources'))
    else:
        return render_template('editSource.html', source_id=source_id,
                               source=originalSource)


# Delete a source
# Original code did not delete all the quotes attributed to the source
# so updated to remove the quotes when the source was removed

@app.route('/source/<int:source_id>/delete/', methods=['GET', 'POST'])
def deleteSource(source_id):
    """ Delete the source and all attributable quotes"""
    sourceToDelete = session.query(
        Source).filter_by(id=source_id).one()
    if 'username' not in login_session:
        return redirect('/login')
    if sourceToDelete.user_id != login_session['user_id']:
        return """<script>function myFunction() {alert(
        'You are not authorized to delete this author. Please create your own
        author in order to delete.');}</script><body onload='myFunction()'>"""
    if request.method == 'POST':
        quotesToDelete = session.query(Quote).filter_by(
                        source_id=source_id).all()
# new section to delete all the quotes before deleting the author.
# If this was not done, then a new author created after would have quotes
# attributed to them incorrectly as they would still reside in the database.
        if len(quotesToDelete) > 0:
            for i in quotesToDelete:
                session.delete(i)
                session.commit()
            flash('Author quotes Successfully Deleted')
        session.delete(sourceToDelete)
        flash('%s Successfully Deleted' % sourceToDelete.name)
        session.commit()
        return redirect(url_for('showSources', source_id=source_id))
    else:
        return render_template('deleteSource.html', source_id=source_id,
                               source=sourceToDelete)


# Show the quotes of a source
@app.route('/source/<int:source_id>/')
@app.route('/source/<int:source_id>/quote/')
def showQuote(source_id):
    """Show all the current quotes from a selected source (author)"""
    source = session.query(Source).filter_by(id=source_id).one()
    items = session.query(Quote).filter_by(
        source_id=source_id).all()
    creator = getUserInfo(source.user_id)
    # quote_creators = getUserInfo(items.user_id)
    curr_user = 0
    if 'username' not in login_session:
        return render_template('publicquotes.html', items=items,
                               source=source, creator=creator)
    else:
        curr_user = login_session['user_id']
        return render_template('quotes.html', items=items, source=source,
                               creator=creator, user=curr_user,)


# Create a new quote
@app.route('/source/<int:source_id>/quote/new/', methods=['GET', 'POST'])
def newQuote(source_id):
    """Create a new quote from a selected source (author)"""
    if 'username' not in login_session:
        return redirect('/login')
    source = session.query(Source).filter_by(id=source_id).one()
    user = login_session['user_id']
# In this application I allow people to add quotes to existing sources
    if request.method == 'POST':
        newItem = Quote(description=request.form[
                 'description'], source_id=source_id, user_id=user)
        if checkInput(newItem.description):
            session.add(newItem)
            session.commit()
            flash('New quote successfully added')
            return redirect(url_for('showQuote', source_id=source_id))
        else:
            flash('Invalid input or input more than 250 char.')
            return redirect(url_for('showQuote', source_id=source_id))
    else:
        return render_template('newQuote.html', source_id=source_id,
                               source=source)


# Edit a quote
@app.route('/source/<int:source_id>/quote/<int:quote_id>/edit',
           methods=['GET', 'POST'])
def editQuote(source_id, quote_id):
    """Edit an existing quote from a source (author)"""
    if 'username' not in login_session:
        return redirect('/login')
    originalQuote = session.query(Quote).filter_by(id=quote_id).one()
    source = session.query(Source).filter_by(id=source_id).one()
    user = login_session['user_id']
    if login_session['user_id'] != originalQuote.user_id:
        return """<script>function myFunction() {alert('You are not authorized
         to edit quotes for this author. Please input your own author in order
          to edit quotes.');}</script><body onload='myFunction()'>"""
    if request.method == 'POST':
        if checkInput(request.form['description']):
            originalQuote.description = request.form['description']
            session.commit()
            flash('Quote Successfully Edited')
            return redirect(url_for('showQuote', source_id=source_id))
        else:
            flash('Invalid input or input more than 250 char.')
            return redirect(url_for('showQuote', source_id=source_id))
    else:
        return render_template('editQuote.html', source_id=source_id,
                               quote_id=quote_id, item=originalQuote)


# Delete a quote
@app.route('/source/<int:source_id>/menu/<int:quote_id>/delete',
           methods=['GET', 'POST'])
def deleteQuote(source_id, quote_id):
    """Delete a single quote from a selected source (author)"""
    if 'username' not in login_session:
        return redirect('/login')
    source = session.query(Source).filter_by(id=source_id).one()
    quoteToDelete = session.query(Quote).filter_by(id=quote_id).one()
    user = login_session['user_id']
    if login_session['user_id'] != quoteToDelete.user_id:
        return """<script>function myFunction() {alert('You are not authorized
        to delete quotes for this author. Please input your own author in order
        to delete quotes.');}</script><body onload='myFunction()'>"""
    if request.method == 'POST':
        session.delete(quoteToDelete)
        session.commit()
        flash('Quote Successfully Deleted')
        return redirect(url_for('showQuote', source_id=source_id))
    else:
        return render_template('deleteQuote.html', item=quoteToDelete,
                               source_id=source_id, quote_id=quote_id)


# Disconnect based on provider - Only one provider in this program.
@app.route('/disconnect')
def disconnect():
    """Disconnect user from their logged in provider"""
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['access_token']

# Add other provide login_session id here
        # if login_session['provider'] == 'facebook':
        #     fbdisconnect()
        #     del login_session['facebook_id']

        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        del login_session['state']      # ???
        flash("You have successfully been logged out.")
        return redirect(url_for('showSources'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showSources'))


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
