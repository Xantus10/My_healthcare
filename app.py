from flask import Flask, render_template, request, send_from_directory, redirect, make_response
from os import path

import dbHandler

# TODO: Login page + functionality, base.html+css, Delete window + functionality, Admin functionality, Doctor page + rejected page, 
# FUTURE TODO: Will have to handle - what if doctor deletes his account and user has open login window with availible doctor and then he scheldules an appointment with him and other corner cases

app = Flask(__name__)


@app.route('/loggedin', methods=['GET', 'POST'])
def loggedIn():
  ix = dbHandler.authorize(int(request.cookies.get('Ssid')), request.cookies.get('Auth'), request.remote_addr)
  return str(ix)


@app.route('/login', methods=['GET', 'POST'])
def loginPage():
  if request.method == 'GET':
    # If we are coming from registration
    if request.args.get('reg'):
      return render_template('login.html', retmsg='Great now log in!')
    # By default return
    return render_template('login.html', retmsg='')
  elif request.method == 'POST':
    username = request.form.get('username')
    password = request.form.get('password')
    if not (username and password):
      return render_template('register.html', retmsg='Please enter all fields')
    ssid, cookie, csrftoken, privLevel = dbHandler.logInUser(username, password, request.remote_addr)
    if ssid == -1:
      return redirect('/')
    resp = make_response(redirect('/loggedin'))
    resp.set_cookie('Auth', cookie)
    resp.set_cookie('Ssid', str(ssid))
    return resp


@app.route('/register', methods=['GET', 'POST'])
def registerPage():
  if request.method == 'GET':
    # By default return
    return render_template('register.html', retmsg='')
  elif request.method == 'POST':
    # Get all input
    firstName = request.form.get('firstName')
    lastName = request.form.get('lastName')
    username = request.form.get('username')
    password = request.form.get('password')
    # Validate all input is present (Is done on client side, but for safety reasons)
    if not (firstName and lastName and username and password):
      return render_template('register.html', retmsg='Please enter all fields')
    # Check if username already exists
    if dbHandler.checkIfUsernameExists(username):
      return render_template('register.html', retmsg='This username already exists')
    # Is doctor?
    isDoctor = True if request.form.get('isDoctor') == 'yes' else False
    if isDoctor:
      # If yes, then get his specialization and validate
      spec = request.form.get('specialization')
      if not spec:
        return render_template('register.html', retmsg='Please enter your specialization as a doctor')
      # Add an unverified doctor
      dbHandler.addUser(username, firstName, lastName, password, 4, spec)
    else:
      # Else add a patient
      dbHandler.addUser(username, firstName, lastName, password, 3)
    # Redirect for login
    return redirect('/login?reg=Y')
    


@app.route('/favicon.ico')
def favicon():
  return send_from_directory(path.join(app.root_path, 'static/icon'), 'favicon.ico', mimetype='image/vnd.microsoft.icon')


@app.route('/', methods=['GET'])
def index():
  return render_template('index.html')


def main():
  dbHandler.initialize()
  app.run(port=80)


if __name__ == '__main__':
  main()
