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
    cursor.execute('CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, firstName TXT NOT NULL, lastName TEXT NOT NULL, salt TEXT NOT NULL, password TEXT NOT NULL, privilegeLevel INT NOT NULL, specialization TEXT);')    # Table for appointments
    cursor.execute('CREATE TABLE IF NOT EXISTS appointments (id INTEGER PRIMARY KEY AUTOINCREMENT, patientId INTEGER NOT NULL, doctorId INTEGER NOT NULL, date TEXT NOT NULL, CONSTRAINT FK_patientId FOREIGN KEY(patientId) REFERENCES users(id),  CONSTRAINT FK_doctorId FOREIGN KEY(doctorId) REFERENCES users(id));')
    # Authentication table (With Session cookie, IP address, Session CSRF Token)
    cursor.execute('CREATE TABLE IF NOT EXISTS auth(ssid INTEGER PRIMARY KEY AUTOINCREMENT, userId INTEGER NOT NULL, cookie TEXT NOT NULL, ipAddress TEXT NOT NULL, CSRFToken TEXT NOT NULL, CONSTRAINT FK_userId FOREIGN KEY(userId) REFERENCES users(id));')
  except sqlite3.Error as e:
    logger.log('An error in SQL syntax occurred while initializing tables')
  except Exception as e:
    logger.log(f'An unexpected error occurred while initializing tables; Error message: {e}')
  db.commit()
  return True


# Log in a user; return ssid(id of a row in db),SessionAuthCookie
def logInUser(username, password, ipAddress):
  try:
    db = sqlite3.connect('data/database.db')
    cursor = db.cursor()
    # Get id, salt and password of a username
    account = cursor.execute('SELECT id, salt, password FROM users WHERE username = ?;', (username,))
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
          return ssid[0], cookie
        logger.log(f'Error in SQL INSERT in "logInUser()", user should have been inserted, however, their ssid was not found')
      else:
        logger.log(f'Password didn\'t match for duser {username}', 2)
    else:
      logger.log(f'Unknown username: {username}', 2)
  except sqlite3.Error as e:
    logger.log(f'An error in SQL syntax occurred while logging in a user; Error message: {e}; Data: {(username, password)}')
  except Exception as e:
    logger.log(f'An unexpected error occurred while logging in a user; Error message: {e}')
  db.commit()
  return -1, ''


# Function for anything, that needs authorization, return ix and csrfToken if it wasn't provided
def authorize(ssid, cookie, ipAddress, csrftoken=''):
  try:
    db = sqlite3.connect('data/database.db')
    cursor = db.cursor()
    if csrftoken == '':
      account = cursor.execute('SELECT userId, CSRFToken from auth WHERE ssid = ? AND cookie = ? AND ipAddress = ?;', (ssid, cookie, ipAddress))
    else:
      account = cursor.execute('SELECT userId from auth WHERE ssid = ? AND cookie = ? AND ipAddress = ? AND CSRFToken = ?;', (ssid, cookie, ipAddress, csrftoken))
    account = account.fetchone()
    # Check if the username exists
    db.commit()
    if account:
      if csrftoken == '':
        return account[0], account[1]
      return account[0]
  except sqlite3.Error as e:
    logger.log(f'An error in SQL syntax occurred while logging in a user; Error message: {e}; Data: {(ssid, cookie, ipAddress, csrftoken)}')
  except Exception as e:
    logger.log(f'An unexpected error occurred while logging in a user; Error message: {e}')
  db.commit()
  return -1


def getUserPrivilege(ix):
  try:
    db = sqlite3.connect('data/database.db')
    cursor = db.cursor()
    # If username is in doctors
    res1 = cursor.execute('SELECT privilegeLevel FROM users WHERE id = ?;', (ix,))
    res1 = res1.fetchone()
    db.commit()
    if res1:
      return res1[0]
    logger.log(f'Couldn\'t find row while checking for a privilege level; Error message: {e}; Data: {(ix)}', 2)
  except sqlite3.Error as e:
    logger.log(f'An error in SQL syntax occurred while checking for a privilege level; Error message: {e}; Data: {(ix)}')
  except Exception as e:
    logger.log(f'An unexpected error occurred while checking for a privilege level; Error message: {e}')
  db.commit()
  return -1


# Log out a user
def logOut(ix):
  try:
    db = sqlite3.connect('data/database.db')
    cursor = db.cursor()
    # Find a user
    user = cursor.execute('SELECT username FROM users WHERE id = ?;', (ix,))
    user = user.fetchone()
    if user:
      cursor.execute('DELETE FROM auth WHERE userId = ?', (ix,))
    else:
      # If we were unable to find the ix in users, we log it as a warning
      logger.log(f'Recieved log out request for ix({ix}), however requested row is not present in users table aborting', 2)
  except sqlite3.Error as e:
    logger.log(f'An error in SQL syntax occurred while logging out a user; Error message: {e}; Data: {(ix)}')
  except Exception as e:
    logger.log(f'An unexpected error occurred while logging out a user; Error message: {e}')
  db.commit()
  return True


# Return True if Username was found in table
def checkIfUsernameExists(username):
  try:
    db = sqlite3.connect('data/database.db')
    cursor = db.cursor()
    # If username is in users
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
  db.commit()
  return True


#REMOVE FROM FINAL VERSION
def selectall(): # Used for displaying data REMOVE FROM FINAL VERSION
  db = sqlite3.connect('data/database.db') #REMOVE FROM FINAL VERSION
  cursor = db.cursor()#REMOVE FROM FINAL VERSION
  res1 = cursor.execute('SELECT * FROM users;')#REMOVE FROM FINAL VERSION
  res1 = res1.fetchall()#REMOVE FROM FINAL VERSION
  db.commit()#REMOVE FROM FINAL VERSION
  return res1#REMOVE FROM FINAL VERSION
#REMOVE FROM FINAL VERSION


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
  except sqlite3.Error as e:
    logger.log(f'An error in SQL syntax occurred while adding a user {privilegeLevel}; Error message: {e}; Data: {(username, firstName, lastName, salt, password, specialization)}')
  except Exception as e:
    logger.log(f'An unexpected error occurred while adding a user {privilegeLevel}; Error message: {e}')
  db.commit()
  return True


# Validate a doctor (set his privilegeLevel to 2)
def validateDoctor(ix):
  try:
    db = sqlite3.connect('data/database.db')
    cursor = db.cursor()
    # Find a user
    doctor = cursor.execute('SELECT privilegeLevel FROM users WHERE id = ?;', (ix,))
    doctor = doctor.fetchone()
    if doctor:
      if doctor[0] != 4:
        logger.log(f'Tried to validate a user with privilegeLevel other than 4 ({doctor[0]}) for user with id ({ix}) aborting', 2)
        db.commit()
        return False
      # Change the privilegeLevel
      cursor.execute('UPDATE users SET privilegeLevel=2 WHERE id = ?;', (ix,))
    else:
      # If we were unable to find the id in users, we log it as a warning
      logger.log(f'Recieved validate request for id({ix}), however requested row is not present in users table aborting', 2)
  except sqlite3.Error as e:
    logger.log(f'An error in SQL syntax occurred while validating a doctor; Error message: {e}; Data: {(ix)}')
  except Exception as e:
    logger.log(f'An unexpected error occurred while validating a doctor; Error message: {e}')
  db.commit()
  return True


# Reject a doctor (Set his privilegeLevel to 10, he is able to log in and choose to delete his account)
def rejectDoctor(ix):
  try:
    db = sqlite3.connect('data/database.db')
    cursor = db.cursor()
    # Find a user
    doctor = cursor.execute('SELECT privilegeLevel FROM users WHERE id = ?;', (ix,))
    doctor = doctor.fetchone()
    if doctor:
      if doctor[0] != 4:
        logger.log(f'Tried to reject a user with privilegeLevel other than 4 ({doctor[0]}) for user with id ({ix}) aborting', 2)
        db.commit()
        return False
      # Change the privilegeLevel
      cursor.execute('UPDATE users SET privilegeLevel=10 WHERE id = ?;', (ix,))
    else:
      # If we were unable to find the id in users, we log it as a warning
      logger.log(f'Recieved reject request for id({ix}), however requested row is not present in users table aborting', 2)
  except sqlite3.Error as e:
    logger.log(f'An error in SQL syntax occurred while validating a doctor; Error message: {e}; Data: {(ix)}')
  except Exception as e:
    logger.log(f'An unexpected error occurred while validating a doctor; Error message: {e}')
  db.commit()
  return True


def getGroupFromPrivilege(privLevel):
  try:
    db = sqlite3.connect('data/database.db')
    cursor = db.cursor()
    # Get all users of a privilege
    res1 = cursor.execute('SELECT id, firstName, lastName, specialization FROM users WHERE privilegeLevel = ?;', (privLevel,))
    res1 = res1.fetchall()
    db.commit()
    if res1:
      return res1
    return []
  except sqlite3.Error as e:
    logger.log(f'An error in SQL syntax occurred while retrieving users of privilege level; Error message: {e}; Data: {(privLevel)}')
  except Exception as e:
    logger.log(f'An unexpected error occurred while retrieving users of privilege level; Error message: {e}')
  db.commit()
  return []


def removeUser(ix):
  try:
    db = sqlite3.connect('data/database.db')
    cursor = db.cursor()
    # Find a user
    user = cursor.execute('SELECT username FROM users WHERE id = ?;', (ix,))
    user = user.fetchone()
    if user:
      cursor.execute('DELETE FROM users WHERE id = ?', (ix,))
    else:
      # If we were unable to find the id in users, we log it as a warning
      logger.log(f'Recieved remove request for id({ix}), however requested row is not present in users table aborting', 2)
  except sqlite3.Error as e:
    logger.log(f'An error in SQL syntax occurred while removing a user; Error message: {e}; Data: {(ix)}')
  except Exception as e:
    logger.log(f'An unexpected error occurred while removing a user; Error message: {e}')
  db.commit()
  return True


# Make an appointment with doctor
def makeAnAppointment(patientId, doctorId, date):
  try:
    db = sqlite3.connect('data/database.db')
    cursor = db.cursor()
    # Check if the appointment doesn't already exist
    res = cursor.execute('SELECT id FROM appointments WHERE patientId = ? AND doctorId = ? AND date = ?;', (patientId, doctorId, date))
    res = res.fetchall()
    if res:
      # If it exists we log it as 'Message' for now
      logger.log(f'User {patientId} tried appointing another appointment with doctor {doctorId}, while his appointment is already present', 1)
    else:
      # If it does not exist we will create one
      cursor.execute('INSERT INTO appointments(patientId, doctorId, date) VALUES(?, ?, ?);', (patientId, doctorId, date))
  except sqlite3.Error as e:
    logger.log(f'An error in SQL syntax occurred while making an appointment; Error message: {e}; Data: {(patientId, doctorId, date)}')
  except Exception as e:
    logger.log(f'An unexpected error occurred while making an appointment; Error message: {e}')
  db.commit()
  return True


# Can either get appointments by patientId or doctorId
def getAppointments(ix, sideOfAppointments='PATIENT'):
  try:
    db = sqlite3.connect('data/database.db')
    cursor = db.cursor()
    if sideOfAppointments == 'PATIENT':
      res = cursor.execute('SELECT appointments.id, users.firstName, users.lastName, appointments.date FROM appointments INNER JOIN users ON appointments.doctorId = users.id WHERE appointments.patientId = ? ORDER BY appointments.date ASC;', (ix,))
    elif sideOfAppointments == 'DOCTOR':
      res = cursor.execute('SELECT appointments.id, users.firstName, users.lastName, appointments.date FROM appointments INNER JOIN users ON appointments.patientId = users.id WHERE appointments.doctorId = ? ORDER BY appointments.date ASC;', (ix,))
    res = res.fetchall()
    db.commit()
    if res:
      return res
    else:
      return []
  except sqlite3.Error as e:
    logger.log(f'An error in SQL syntax occurred while getting appointments; Error message: {e}; Data: {(ix, sideOfAppointments)}')
  except Exception as e:
    logger.log(f'An unexpected error occurred while getting appointments; Error message: {e}')
  db.commit()
  return []


def initializeAdminAccount():
  if not checkIfUsernameExists('Admin12345'):
    addUser('Admin12345', 'Admin12345', 'Admin12345', 'Admin12345', 1)


# After having an appointment, doctor can erase it
def doneAppointment(ix):
  pass
