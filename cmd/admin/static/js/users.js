function addUser() {
  $("#addUserModal").modal();
}

function confirmAddUser() {
  var _csrftoken = $("#csrftoken").val();

  var _url = window.location.pathname;

  var _username = $("#user_username").val();
  var _fullname = $("#user_fullname").val();
  var _password = $("#user_password").val();

  var data = {
    csrftoken: _csrftoken,
    action: 'add',
    username: _name,
    fullname: _type,
    password: _password,
    admin: true
  };
  sendPostRequest(data, _url, _url, false);
}
