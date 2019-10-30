function addUser() {
  $("#user_username").val('');
  $("#user_email").val('');
  $("#user_fullname").val('');
  $("#user_password").val('');
  $("#addUserModal").modal();
}

function confirmAddUser() {
  var _csrftoken = $("#csrftoken").val();

  var _url = window.location.pathname;

  var _username = $("#user_username").val();
  var _email = $("#user_email").val();
  var _fullname = $("#user_fullname").val();
  var _password = $("#user_password").val();

  var data = {
    csrftoken: _csrftoken,
    action: 'add',
    username: _username,
    email: _email,
    fullname: _fullname,
    password: _password,
    admin: false
  };
  sendPostRequest(data, _url, _url, false);
}

function confirmDeleteUser(_user) {
  var modal_message = 'Are you sure you want to delete the user ' + _user + '?';
  $("#confirmModalMessage").text(modal_message);
  $('#confirm_action').click(function () {
    $('#confirmModal').modal('hide');
    deleteUser(_user);
  });
  $("#confirmModal").modal();
}

function changeAdminUser(_user) {
  var _csrftoken = $("#csrftoken").val();
  var _value = $("#" + _user).is(':checked');

  var _url = window.location.pathname;

  var data = {
    csrftoken: _csrftoken,
    action: 'admin',
    username: _user,
    admin: _value,
  };
  sendPostRequest(data, _url, '', false);
}

function deleteUser(_user) {
  var _csrftoken = $("#csrftoken").val();

  var _url = window.location.pathname;

  var data = {
    csrftoken: _csrftoken,
    action: 'remove',
    username: _user,
  };
  sendPostRequest(data, _url, _url, false);
}

function showAPIToken(_token, _exp, _username) {
  $("#user_api_token").val(_token);
  $("#user_token_expiration").val(_exp);
  $("#user_token_username").val(_username);
  $("#apiTokenModal").modal();
}

function refreshUserToken() {
  var _csrftoken = $("#csrftoken").val();
  var _username = $("#user_token_username").val();

  var data = {
    csrftoken: _csrftoken,
    username: _username,
  };
  sendPostRequest(data, '/tokens/' + _username + '/refresh', '', false, function (data) {
    console.log(data);
    $("#user_api_token").val(data.token);
    $("#user_token_expiration").val(data.exp_ts);
  });
}
