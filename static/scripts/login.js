function checkAll() {
  if (!checkUsername()) {
    document.getElementById('msg').innerHTML = "Please enter a username";
    document.getElementById('submit').disabled = true;
  } else if (!checkPassword()) {
    document.getElementById('msg').innerHTML = "Please enter a password";
    document.getElementById('submit').disabled = true;
  } else {
    document.getElementById('msg').innerHTML = "";
    document.getElementById('submit').disabled = false;
  }
}

function checkUsername() {
  return document.getElementById('username').value != "";
}

function checkPassword() {
  let password = document.getElementById('password').value;
  if(password.length > 0){
    let lowercaseLetters = "abcdefghijklmnopqrstuvwxyz"
    let uppercaseLetters = lowercaseLetters.toUpperCase();
    let numbers = "0123456789"
    let lowercaseCheck = false;
    let uppercaseCheck = false;
    let numberCheck = false;
    let lengthCheck = false;
    let i = 0;
    let char = ''
    while((!lowercaseCheck || !uppercaseCheck || !numberCheck || !lengthCheck) && i < password.length){
      if((!lowercaseCheck) && (lowercaseLetters.search(char) != -1)){
        lowercaseCheck = true;
      } else if((!uppercaseCheck) && (uppercaseLetters.search(char) != -1)){
        uppercaseCheck = true;
      }else if((!numberCheck) && (numbers.search(char) != -1)){
        numberCheck = true;
      }else if((!lengthCheck) && (password.length >= 8)){
        lengthCheck = true;
      }
      i++;
    }
    return lowercaseCheck && uppercaseCheck && numberCheck && lengthCheck;
  }
  return false;
}
