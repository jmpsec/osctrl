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

function toggleAPIToken() {
  var tokenField = document.getElementById("profile_api_token");
  var tokenValue = document.getElementById("profile_api_token_value").value;
  if (tokenField.type === "password") {
    tokenField.type = "text";
    tokenField.value = tokenValue;
    $("#button-eye").html('<i class="fas fa-eye-slash"></i>');
  } else {
    tokenField.type = "password";
    tokenField.value = "••••••••••••••••••••••••••••••";
    $("#button-eye").html('<i class="fas fa-eye"></i>');
  }
}

function refreshUserToken() {
  $("#refreshTokenButton").prop("disabled", true);
  $("#refreshTokenButton").html(
    '<i class="fa fa-cog fa-spin fa-2x fa-fw"></i>'
  );
  var _csrftoken = $("#csrftoken").val();
  var _username = $("#profile_token_username").val();
  var _exp_hours = parseInt($("#profile_exp_hours").val());
  var data = {
    csrftoken: _csrftoken,
    username: _username,
    exp_hours: _exp_hours,
  };
  sendPostRequest(
    data,
    "/tokens/" + _username + "/refresh",
    "",
    false,
    function (data) {
      console.log(data);
      $("#profile_api_token_value").val(data.token);
      var expDiv = document.getElementById('profile_token_exp');
      expDiv.innerText = data.expiration;
      $("#refreshTokenButton").prop("disabled", false);
      $("#refreshTokenButton").html('<i class="fas fa-sync-alt"></i>');
    }
  );
}
