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
    username: _username,
    fullname: _fullname,
    password: _password,
    admin: true
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
