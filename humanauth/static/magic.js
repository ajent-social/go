// Copies the magic-link token from the URL fragment into the redeem form,
// drops the fragment from the address bar, and submits the form once.
(function () {
  "use strict";
  var form = document.getElementById("humanauth-magic");
  if (!form) {
    return;
  }
  var input = form.querySelector('input[name="token"]');
  var token = location.hash.slice(1);
  if (!input || !token) {
    return;
  }
  input.value = token;
  history.replaceState(null, "", location.pathname + location.search);
  var submitted = false;
  form.addEventListener("submit", function (ev) {
    if (submitted) {
      ev.preventDefault();
    }
    submitted = true;
  });
  submitted = true;
  form.submit();
})();
