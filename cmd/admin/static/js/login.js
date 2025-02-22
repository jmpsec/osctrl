function sendLogin() {
  var _user = $("#login_user").val();
  var _password = $("#login_password").val();

  var _url = '/login';
  var data = {
      username: _user,
      password: _password
  };
  sendPostRequest(data, _url, '', false, function(_data){
    window.location.replace(_data.message);
  });
}

function sendLogout() {
  var _csrf = $("#csrftoken").val();

  var _url = '/logout';
  var data = {
    csrftoken: _csrf
  };
  sendPostRequest(data, _url, '/logout', false);
}

$("#login_password").keyup(function(event) {
  if (event.keyCode === 13) {
      $("#login_button").click();
  }
});
