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
