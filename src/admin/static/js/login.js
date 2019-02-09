function sendLogin() {
  var _user = $("#login_user").val();
  var _password = $("#login_password").val();
  
  var _url = '/login';
  var data = {
      username: _user,
      password: _password
  };
  sendPostRequest(data, _url, '/dashboard');
}

function sendLogout() {
  var _csrf = $("#csrftoken").val();
  
  var _url = '/logout';
  var data = {
    csrftoken: _csrf
  };
  sendPostRequest(data, _url, '/login');
}

$("#login_password").keyup(function(event) {
  if (event.keyCode === 13) {
      $("#login_button").click();
  }
});
