function showSpec() {
  let checkbox = document.getElementById('isDoctor');
  let spec = document.getElementById('specialization');
  let speci = document.getElementById('specI');

  if (checkbox.checked) {
    spec.style.display = "inline-block";
    speci.style.display = "var(--fa-display,inline-block)";
  } else {
    spec.style.display = "none";
    speci.style.display = "none";
  }
}

function checkAll() {
  if (!checkFName()) {
    document.getElementById('msg').innerHTML = "Please enter your first name";
    document.getElementById('submit').disabled = true;
  } else if (!checkLName()) {
    document.getElementById('msg').innerHTML = "Please enter your last name";
    document.getElementById('submit').disabled = true;
  } else if (!checkUsername()) {
    document.getElementById('msg').innerHTML = "Please enter a username";
    document.getElementById('submit').disabled = true;
  } else if (!checkPassword()) {
    document.getElementById('msg').innerHTML = "A password must be longer than 8 characters and contain a capital letter and a number";
    document.getElementById('submit').disabled = true;
  } else if (!checkSpec()) {
    document.getElementById('msg').innerHTML = "Please enter your specialization";
    document.getElementById('submit').disabled = true;
  } else {
    document.getElementById('msg').innerHTML = "";
    document.getElementById('submit').disabled = false;
  }
}

function checkUsername() {
  return document.getElementById('username').value != "";
}

function checkFName() {
  return document.getElementById('firstName').value != "";
}

function checkLName() {
  return document.getElementById('lastName').value != "";
}

function checkSpec() {
  let chBox = document.getElementById('isDoctor');
  if (chBox.checked) {
    return document.getElementById('specialization').value != "";
  }
  return true;
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
