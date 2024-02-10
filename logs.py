from datetime import datetime

# 1-3 for Message (*), Warning (#), Error (!)
def log(msg: str, type=3):
  try:
    # Identificators for messages ([*], [!], etc.)
    if type == 1:
      descriptionChar = '*'
    elif type == 2:
      descriptionChar = '#'
    elif type == 3:
      descriptionChar = '!'
    else:
      # Use [U] for Unidentified logs
      descriptionChar = 'U'
    # Format the log Into: [ID] (date time) - message with newlines replaced with ;;
    toLog = f'[{descriptionChar}] ({datetime.now().strftime("%d.%m.%Y %H:%M:%S")}) - {msg.replace(chr(10), ";;")}{chr(10)}'
    # Write to logfile
    with open('data/log.txt', 'a') as f:
      f.write(toLog)
  except Exception as e:
    print(f'ERROR Unexpected Exception occurred while logging: {e}')
