import sqlite3
from hashlib import sha256
from secrets import token_hex

import logs as logger


# Hash a password, returns salt,hash tuple
def hashPassword(password: str):
  try:
    # Random salt
    salt = token_hex(32)
    # Hashed password with salt
    hashed = sha256(bytes.fromhex(salt) + bytes(password, 'utf-8')).hexdigest()
    return salt, hashed
  except Exception as e:
    logger.log(f'An unexpected error occurred while hashing a password; Error message: {e}')
  return '', ''


# Check provided password, salt with a hash
def checkHashedPassword(password: str, salt: str, checkHash: str):
  try:
    return sha256(bytes.fromhex(salt) + bytes(password, 'utf-8')).hexdigest() == checkHash
  except Exception as e:
    logger.log(f'An unexpected error occurred while checking a hashed password; Error message: {e}')
  return ''


# Reset the database
def reset():
  pass


# Initialize all database tables
def initialize():
  try:
    db = sqlite3.connect('data/database.db')
    cursor = db.cursor()
    # Table for users (Privilege level: 1-Admin 2-VerifiedDoctor 3-Patient 4-UnverifiedDoctor 10-RejectedDoctor)
    cursor.execute('CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, firstName TXT NOT NULL, lastName TEXT NOT NULL, salt TEXT NOT NULL, password TEXT NOT NULL, privilegeLevel INT NOT NULL, specialization TEXT);')
    # Table for appointments
    cursor.execute('CREATE TABLE IF NOT EXISTS appointments (id INTEGER PRIMARY KEY AUTOINCREMENT, patientId INTEGER NOT NULL, doctorId INTEGER NOT NULL, CONSTRAINT FK_patientId FOREIGN KEY(patientId) REFERENCES users(id),  CONSTRAINT FK_doctorId FOREIGN KEY(doctorId) REFERENCES users(id));')
    # Authentication table (With Session cookie, IP address, Session CSRF Token)
    cursor.execute('CREATE TABLE IF NOT EXISTS auth(ssid INTEGER PRIMARY KEY AUTOINCREMENT, userId INTEGER NOT NULL, cookie TEXT NOT NULL, ipAddress TEXT NOT NULL, CSRFToken TEXT NOT NULL, CONSTRAINT FK_userId FOREIGN KEY(userId) REFERENCES users(id));')
    db.commit()
  except sqlite3.Error as e:
    logger.log('An error in SQL syntax occurred while initializing tables')
  except Exception as e:
    logger.log(f'An unexpected error occurred while initializing tables; Error message: {e}')
  return True


# Log in a user; return ssid(id of a row in db),SessionAuthCookie,CSRFToken,userPrivLevel
def logInUser(username, password, ipAddress):
  try:
    db = sqlite3.connect('data/database.db')
    cursor = db.cursor()
    # Get id, salt and password of a username
    account = cursor.execute('SELECT id, salt, password, privilegeLevel FROM users WHERE username = ?;', (username,))
    account = account.fetchone()
    # Check if the username exists
    if account:
      # Check if the password is right
      if (checkHashedPassword(password, account[1], account[2])):
        # Check if someone is logged in, however their browser does not remember 'auth' cookie, then remove their record
        checkloggedin = cursor.execute('SELECT ssid FROM auth WHERE userId = ?;', (account[0],))
        if (checkloggedin.fetchone()):
          cursor.execute('DELETE FROM auth WHERE userId = ?;', (account[0],))
        # Authorization cookie
        cookie = token_hex(32)
        # CSRF token
        csrftoken = token_hex(32)
        # INSERT into authorization table
        cursor.execute('INSERT INTO auth(userId, cookie, ipAddress, CSRFToken) VALUES(?, ?, ?, ?);', (account[0], cookie, ipAddress, csrftoken))
        # Get the SSID of the record in auth table
        ssid = cursor.execute('SELECT ssid FROM auth WHERE userId = ?;', (account[0],))
        ssid = ssid.fetchone()
        if ssid:
          db.commit()
          return ssid[0], cookie, csrftoken, account[3]
        logger.log(f'Error in SQL INSERT in "logInUser()", user should have been inserted, however, their ssid was not found')
      else:
        logger.log(f'Password didn\'t match for duser {username}', 2)
    else:
      logger.log(f'Unknown username: {username}', 2)
    db.commit()
  except sqlite3.Error as e:
    logger.log(f'An error in SQL syntax occurred while logging in a user; Error message: {e}; Data: {(username, password)}')
  except Exception as e:
    logger.log(f'An unexpected error occurred while logging in a user; Error message: {e}')
  return -1, '', '', -1


# Function for anything, that needs authorization
def authorize(ssid, cookie, ipAddress, csrftoken=''):
  try:
    db = sqlite3.connect('data/database.db')
    cursor = db.cursor()
    if csrftoken == '':
      account = cursor.execute('SELECT userId from auth WHERE ssid = ? AND cookie = ? AND ipAddress = ?;', (ssid, cookie, ipAddress))
    else:
      account = cursor.execute('SELECT userId from auth WHERE ssid = ? AND cookie = ? AND ipAddress = ? AND CSRFToken = ?;', (ssid, cookie, ipAddress, csrftoken))
    account = account.fetchone()
    # Check if the username exists
    if account:
      return account[0]
    db.commit()
  except sqlite3.Error as e:
    logger.log(f'An error in SQL syntax occurred while logging in a user; Error message: {e}; Data: {(ssid, cookie, ipAddress, csrftoken)}')
  except Exception as e:
    logger.log(f'An unexpected error occurred while logging in a user; Error message: {e}')
  return -1


# Log out a user
def logOut(ssid, cookie):
  pass


# Return True if Username was found in table
def checkIfUsernameExists(username):
  try:
    db = sqlite3.connect('data/database.db')
    cursor = db.cursor()
    # If username is in doctors
    res1 = cursor.execute('SELECT * FROM users WHERE username = ?;', (username,))
    res1 = res1.fetchall()
    db.commit()
    if res1:
      return True
    return False
  except sqlite3.Error as e:
    logger.log(f'An error in SQL syntax occurred while checking if a username already exists; Error message: {e}; Data: {(username)}')
  except Exception as e:
    logger.log(f'An unexpected error occurred while checking if a username already exists; Error message: {e}')
  return True


def selectall(): # Used for displaying data REMOVE FROM FINAL VERSION
  db = sqlite3.connect('data/database.db')
  cursor = db.cursor()
  # If username is in doctors
  res1 = cursor.execute('SELECT * FROM users;')
  res1 = res1.fetchall()
  db.commit()
  return res1


# Add a new user (Privilege level: 1-Admin 2-VerifiedDoctor 3-Patient 4-UnverifiedDoctor), Only doctors have specialization
def addUser(username, firstName, lastName, password, privilegeLevel, specialization='NULL'):
  try:
    if not privilegeLevel in [1, 3, 4]:
      logger.log(f'Trying to add a user with unknown or forbidden privilege level ({privilegeLevel}) aborting', 2)
      return False
    db = sqlite3.connect('data/database.db')
    cursor = db.cursor()
    # Hash the password
    salt, hashed = hashPassword(password)
    # Data for INSERT
    data = (username, firstName, lastName, salt, hashed, privilegeLevel, specialization)
    # INSERT into users table (All doctors have to get validated by admin, to obtain privilegeLevel 2)
    cursor.execute('INSERT INTO users(username, firstName, lastName, salt, password, privilegeLevel, specialization) VALUES(?, ?, ?, ?, ?, ?, ?);', data)
    db.commit()
  except sqlite3.Error as e:
    logger.log(f'An error in SQL syntax occurred while adding a user {privilegeLevel}; Error message: {e}; Data: {(username, firstName, lastName, salt, password, specialization)}')
  except Exception as e:
    logger.log(f'An unexpected error occurred while adding a user {privilegeLevel}; Error message: {e}')
  return True


# Validate a doctor (set his privilegeLevel to 2)
def validateDoctor(id):
  try:
    db = sqlite3.connect('data/database.db')
    cursor = db.cursor()
    # Find a user
    doctor = cursor.execute('SELECT privilegeLevel FROM users WHERE id = ?;', (id,))
    doctor = doctor.fetchone()
    if doctor:
      if doctor[0] != 4:
        logger.log(f'Tried to validate a user with privilegeLevel other than 4 ({doctor[0]}) for user with id ({id}) aborting', 2)
        return False
      # Change the privilegeLevel
      cursor.execute('UPDATE users SET privilegeLevel=2 WHERE id = ?;', (id,))
    else:
      # If we were unable to find the id in users, we log it as a warning
      logger.log(f'Recieved validate request for id({id}), however requested row is not present in users table aborting', 2)
    db.commit()
  except sqlite3.Error as e:
    logger.log(f'An error in SQL syntax occurred while validating a doctor; Error message: {e}; Data: {(id)}')
  except Exception as e:
    logger.log(f'An unexpected error occurred while validating a doctor; Error message: {e}')
  return True


# Reject a doctor (Set his privilegeLevel to 10, he is able to log in and choose to delete his account)
def rejectDoctor(id):
  try:
    db = sqlite3.connect('data/database.db')
    cursor = db.cursor()
    # Find a user
    doctor = cursor.execute('SELECT privilegeLevel FROM users WHERE id = ?;', (id,))
    doctor = doctor.fetchone()
    if doctor:
      if doctor[0] != 4:
        logger.log(f'Tried to reject a user with privilegeLevel other than 4 ({doctor[0]}) for user with id ({id}) aborting', 2)
        return False
      # Change the privilegeLevel
      cursor.execute('UPDATE users SET privilegeLevel=10 WHERE id = ?;', (id,))
    else:
      # If we were unable to find the id in users, we log it as a warning
      logger.log(f'Recieved reject request for id({id}), however requested row is not present in users table aborting', 2)
    db.commit()
  except sqlite3.Error as e:
    logger.log(f'An error in SQL syntax occurred while validating a doctor; Error message: {e}; Data: {(id)}')
  except Exception as e:
    logger.log(f'An unexpected error occurred while validating a doctor; Error message: {e}')
  return True


def removeUser(id):
  pass


# Make an appointment with doctor
def makeAnAppointment(patientId, doctorId):
  try:
    db = sqlite3.connect('data/database.db')
    cursor = db.cursor()
    # Check if the appointment doesn't already exist
    res = cursor.execute('SELECT id FROM patientsdoctorsAppointments WHERE patientId = ? AND doctorId = ?;', (patientId, doctorId))
    res = res.fetchall()
    if res:
      # If it exists we log it as 'Message' for now
      logger.log(f'User {patientId} tried appointing another appointment with doctor {doctorId}, while his appointment is already present', 1)
    else:
      # If it does not exist we will create one
      cursor.execute('INSERT INTEGERO patientsdoctorsAppointments(patientId, doctorId) VALUES(?, ?);', (patientId, doctorId))
    db.commit()
  except sqlite3.Error as e:
    logger.log(f'An error in SQL syntax occurred while making an appointment; Error message: {e}; Data: {(patientId, doctorId)}')
  except Exception as e:
    logger.log(f'An unexpected error occurred while making an appointment; Error message: {e}')
  return True


# After having an appointment, doctor can erase it
def doneAppointment(id):
  pass
