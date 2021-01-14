function profileChangePassword(_username) {
  $("#new_password").val('');
  $("#confirm_password").val('');
  $("#change_password_username").val(_username);
  $("#change_password_header").text('Change Password for ' + _username);
  $("#changePasswordModal").modal();
}

function profileConfirmChangePassword() {
  var _csrftoken = $("#csrftoken").val();

  var _url = window.location.pathname;

  var _username = $("#change_password_username").val();
  var _newpassword = $("#new_password").val();
  var _oldpassword = $("#old_password").val();

  var data = {
    csrftoken: _csrftoken,
    action: 'change_password',
    username: _username,
    new_password: _newpassword,
    old_password: _oldpassword,
  };
  sendPostRequest(data, _url, _url, false);
}

function profileEditSave() {
  var _csrftoken = $("#csrftoken").val();

  var _url = window.location.pathname;

  var _username = $("#profile_username").val();
  var _email = $("#profile_email").val();
  var _fullname = $("#profile_fullname").val();

  var data = {
    csrftoken: _csrftoken,
    action: 'edit',
    username: _username,
    email: _email,
    fullname: _fullname,
  };
  sendPostRequest(data, _url, '', true);
}
