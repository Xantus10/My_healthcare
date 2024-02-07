from flask import Flask, render_template, request, send_from_directory, redirect
from os import path

import dbHandler

# TODO: Register page + functionality, Login page + functionality, base.html+css, Delete window + functionality, Admin functionality, Doctor page + rejected page, 
# FUTURE TODO: Will have to handle - what if doctor deletes his account and user has open login window with availible doctor and then he scheldules an appointment with him and other corner cases

app = Flask(__name__)


@app.route('/favicon.ico')
def favicon():
  return send_from_directory(path.join(app.root_path, 'static/icon'), 'favicon.ico', mimetype='image/vnd.microsoft.icon')


@app.route('/', methods=['GET'])
def index():
  return render_template('index.html')


def main():
  app.run(port=80)


if __name__ == '__main__':
  main()
