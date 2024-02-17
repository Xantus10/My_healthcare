from flask import Flask, render_template, request, send_from_directory, redirect, make_response
from os import path

import dbHandler

# TODO: Doctor/patient page
# FUTURE TODO: HMAC for cookies and csrf tokens, Will have to handle - what if doctor deletes his account and user has open login window with availible doctor and then he scheldules an appointment with him and other corner cases

app = Flask(__name__)


@app.route('/delete', methods=['POST'])
def delete():
  if request.method == 'POST':
    ssid = int(request.cookies.get('Ssid'))
    cookie = request.cookies.get('Auth')
    ipAddr = request.remote_addr
    csrfToken = request.form.get('CSRFToken')
    if not csrfToken:
      return redirect('/') # For now redirect those unauthorized
    ix = dbHandler.authorize(ssid, cookie, ipAddr, csrfToken)
    if ix == -1:
      return redirect('/')
    dbHandler.logOut(ix)
    dbHandler.removeUser(ix)
    resp = make_response(redirect('/'))
    resp.delete_cookie('Ssid')
    resp.delete_cookie('Auth')
    return resp


@app.route('/logout', methods=['POST'])
def logOut():
  if request.method == 'POST':
    ssid = int(request.cookies.get('Ssid'))
    cookie = request.cookies.get('Auth')
    ipAddr = request.remote_addr
    csrfToken = request.form.get('CSRFToken')
    if not csrfToken:
      return redirect('/') # For now redirect those unauthorized
    ix = dbHandler.authorize(ssid, cookie, ipAddr, csrfToken)
    if ix == -1:
      return redirect('/')
    dbHandler.logOut(ix)
    resp = make_response(redirect('/'))
    resp.delete_cookie('Ssid')
    resp.delete_cookie('Auth')
    return resp


@app.route('/validate', methods=['POST'])
def validateOrRejectDoctor():
  if request.method == 'POST':
    ssid = int(request.cookies.get('Ssid'))
    cookie = request.cookies.get('Auth')
    ipAddr = request.remote_addr
    csrfToken = request.form.get('CSRFToken')
    if not csrfToken:
      return redirect('/') # For now redirect those unauthorized
    ix = dbHandler.authorize(ssid, cookie, ipAddr, csrfToken)
    if ix == -1:
      return redirect('/')
    if int(dbHandler.getUserPrivilege(ix)) != 1:
      return redirect('/')
    lenOflist = request.form.get('lenOflist', type=int)
    for i in range(lenOflist):
      userId = request.form.get(f'indexOf{i}', type=int)
      valOrRej = request.form.get(f'radio{i}')
      if valOrRej == 'Validate':
        dbHandler.validateDoctor(userId)
      elif valOrRej == 'Reject':
        dbHandler.rejectDoctor(userId)
    return redirect('/loggedin')


@app.route('/makeAppointment', methods=['POST'])
def makeAppointment():
  if request.method == 'POST':
    ssid = int(request.cookies.get('Ssid'))
    cookie = request.cookies.get('Auth')
    ipAddr = request.remote_addr
    csrfToken = request.form.get('CSRFToken')
    if not csrfToken:
      return redirect('/') # For now redirect those unauthorized
    ix = dbHandler.authorize(ssid, cookie, ipAddr, csrfToken)
    if ix == -1:
      return redirect('/')
    if int(dbHandler.getUserPrivilege(ix)) != 3:
      return redirect('/')
    doctor = request.form.get('doctor', type=int)
    date = request.form.get('date') # %Y-%m-%d
    # maybe also verify if doctor is present in doctors table
    if doctor and date:
      dbHandler.makeAnAppointment(ix, doctor, date)
    return redirect('/loggedin')


@app.route('/loggedin', methods=['GET', 'POST'])
def loggedIn():
  if request.method == 'GET':
    ssid = int(request.cookies.get('Ssid'))
    cookie = request.cookies.get('Auth')
    ipAddr = request.remote_addr
    ix, CSRFToken = dbHandler.authorize(ssid, cookie, ipAddr)
    if ix == -1:
      return redirect('/login')
    privilegeLevel = dbHandler.getUserPrivilege(ix)
    if privilegeLevel == 1:
      doctorsList = dbHandler.getGroupFromPrivilege(4)
      return render_template('adminView.html', csrfToken=CSRFToken, lenOflist=len(doctorsList), dlist = doctorsList)
    elif privilegeLevel == 2:
      pass
    elif privilegeLevel == 3:
      doctorsList = dbHandler.getGroupFromPrivilege(2)
      return render_template('patient.html', csrfToken=CSRFToken, lenOflist=len(doctorsList), dlist = doctorsList)
    elif privilegeLevel == 4:
      return render_template('pendingDoctor.html', csrfToken=CSRFToken)
    elif privilegeLevel == 10:
      return render_template('rejectedDoctor.html', csrfToken=CSRFToken)
    return render_template('base.html')


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
    ssid, cookie = dbHandler.logInUser(username, password, request.remote_addr)
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
  dbHandler.initializeAdminAccount()
  app.run(port=80)


if __name__ == '__main__':
  main()
