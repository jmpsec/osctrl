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
  var _admin = $("#user_admin").is(':checked');
  var _token = $("#user_token").is(':checked');

  var data = {
    csrftoken: _csrftoken,
    action: 'add',
    username: _username,
    email: _email,
    fullname: _fullname,
    password: _password,
    admin: _admin,
    token: _token
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

  if (_value) {
    $('#permissions-button-' + _user).hide();
  } else {
    $('#permissions-button-' + _user).show();
  }

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
  $("#refreshTokenButton").prop("disabled", true);
  $("#refreshTokenButton").html('<i class="fa fa-cog fa-spin fa-2x fa-fw"></i>');
  var _csrftoken = $("#csrftoken").val();
  var _username = $("#user_token_username").val();

  var data = {
    csrftoken: _csrftoken,
    username: _username,
  };
  sendPostRequest(data, '/tokens/' + _username + '/refresh', '', false, function (data) {
    console.log(data);
    $("#user_api_token").val(data.token);
    $("#user_token_expiration").val(data.expiration);
    $("#refreshTokenButton").prop("disabled", false);
    $("#refreshTokenButton").text('Refresh');
  });
}

function showPermissions(_username) {
  $("#username_permissions").val(_username);
  sendGetRequest('/users/permissions/' + _username, false, function (data) {
    $('.switch-env-permission').each(function () {
      var _env = $(this).attr('id');
      if (data.environments) {
        if (data.environments[_env]) {
          $(this).attr('checked', true);
        } else {
          $(this).attr('checked', false);
        }
      } else {
        $(this).attr('checked', false);
      }
    });
    if (data.query) {
      $("#permission-queries").attr('checked', true);
    } else {
      $("#permission-queries").attr('checked', false);
    }
    if (data.carve) {
      $("#permission-carves").attr('checked', true);
    } else {
      $("#permission-carves").attr('checked', false);
    }
  });
  $("#permissionsModal").modal();
}

function savePermissions() {
  var _csrftoken = $("#csrftoken").val();
  var _username = $("#username_permissions").val();

  var _queries = $("#permission-queries").is(':checked');
  var _carves = $("#permission-carves").is(':checked');

  var _envs = {};
  $('.switch-env-permission').each(function () {
    _envs[$(this).attr('id')] = $(this).prop('checked');
  });
  var data = {
    csrftoken: _csrftoken,
    environments: _envs,
    query: _queries,
    carve: _carves,
  };
  sendPostRequest(data, '/users/permissions/' + _username, '', false, function (data) {
    console.log(data);
  });
}
