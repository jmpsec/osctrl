function addUser() {
  $("#user_username").val("");
  $("#user_email").val("");
  $("#user_fullname").val("");
  $("#user_password").val("");
  $("#addUserModal").modal();
}

function confirmAddUser() {
  var _csrftoken = $("#csrftoken").val();

  var _url = window.location.pathname;

  var _username = $("#user_username").val();
  var _email = $("#user_email").val();
  var _fullname = $("#user_fullname").val();
  var _password = $("#user_password").val();
  var _admin = $("#user_admin").is(":checked");
  var _service = $("#user_service").is(":checked");
  var _token = $("#user_token").is(":checked");
  var _env_list = $("#user_environments").val();

  // Check if all environments have been selected
  if (_env_list.includes("all_environments_99")) {
    _env_list = [];
    $("#user_environments option").each(function () {
      if ($(this).val() !== "" && $(this).val() !== "all_environments_99") {
        _env_list.push($(this).val());
      }
    });
  }

  var data = {
    csrftoken: _csrftoken,
    action: "add",
    username: _username,
    email: _email,
    fullname: _fullname,
    new_password: _password,
    admin: _admin,
    service: _service,
    token: _token,
    environments: _env_list,
  };
  sendPostRequest(data, _url, _url, false);
}

function confirmDeleteUser(_user) {
  var modal_message = "Are you sure you want to delete the user " + _user + "?";
  $("#confirmModalMessage").text(modal_message);
  $("#confirm_action").click(function () {
    $("#confirmModal").modal("hide");
    deleteUser(_user);
  });
  $("#confirmModal").modal();
}

function changeAdminUser(_user) {
  var _csrftoken = $("#csrftoken").val();
  var _value = $("#admin_" + _user).is(":checked");

  if (_value) {
    $("#permissions-button-" + _user).hide();
  } else {
    $("#permissions-button-" + _user).show();
  }

  var _url = window.location.pathname;

  var data = {
    csrftoken: _csrftoken,
    action: "admin",
    username: _user,
    admin: _value,
  };
  sendPostRequest(data, _url, _url, false);
}

function changeServiceUser(_user) {
  var _csrftoken = $("#csrftoken").val();
  var _value = $("#service_" + _user).is(":checked");

  var _url = window.location.pathname;

  var data = {
    csrftoken: _csrftoken,
    action: "service",
    username: _user,
    service: _value,
  };
  sendPostRequest(data, _url, _url, false);
}

function deleteUser(_user) {
  var _csrftoken = $("#csrftoken").val();

  var _url = window.location.pathname;

  var data = {
    csrftoken: _csrftoken,
    action: "remove",
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
  $("#refreshTokenButton").html(
    '<i class="fa fa-cog fa-spin fa-2x fa-fw"></i>'
  );
  var _csrftoken = $("#csrftoken").val();
  var _username = $("#user_token_username").val();
  var _exp_hours = parseInt($("#expiration_hours").val());
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
      $("#user_api_token").val(data.token);
      $("#user_token_expiration").val(data.expiration);
      $("#refreshTokenButton").prop("disabled", false);
      $("#refreshTokenButton").text("Refresh");
    }
  );
}

function showPermissions(_username) {
  $("#username_permissions").val(_username);
  sendGetRequest("/users/permissions/" + _username, false, function (data) {
    for (var key in data) {
      $("." + key + "-env").each(function () {
        var element_id = $(this).attr("id");
        if (element_id.search("permission-read") > 0) {
          $(this).attr("checked", data[key].user);
        }
        if (element_id.search("permission-query") > 0) {
          $(this).attr("checked", data[key].query);
        }
        if (element_id.search("permission-carve") > 0) {
          $(this).attr("checked", data[key].carve);
        }
        if (element_id.search("permission-admin") > 0) {
          $(this).attr("checked", data[key].admin);
        }
      });
    }
  });
  $("#permissionsModal").modal();
}

function savePermissions(_env_perm) {
  var _csrftoken = $("#csrftoken").val();
  var _username = $("#username_permissions").val();

  var _read = $("#" + _env_perm + "-read").is(":checked");
  var _query = $("#" + _env_perm + "-query").is(":checked");
  var _carve = $("#" + _env_perm + "-carve").is(":checked");
  var _admin = $("#" + _env_perm + "-admin").is(":checked");

  var _env = $("#" + _env_perm + "-env").val();
  var data = {
    csrftoken: _csrftoken,
    environment: _env,
    read: _read,
    query: _query,
    carve: _carve,
    admin: _admin,
  };
  sendPostRequest(
    data,
    "/users/permissions/" + _username,
    "",
    false,
    function (data) {
      console.log(data);
    }
  );
}

function changePassword(_username) {
  $("#new_password").val("");
  $("#confirm_password").val("");
  $("#change_password_username").val(_username);
  $("#change_password_header").text("Change Password for " + _username);
  $("#changePasswordModal").modal();
}

function confirmChangePassword() {
  var _csrftoken = $("#csrftoken").val();

  var _url = window.location.pathname;

  var _username = $("#change_password_username").val();
  var _newpassword = $("#new_password").val();

  var data = {
    csrftoken: _csrftoken,
    action: "edit",
    username: _username,
    new_password: _newpassword,
  };
  sendPostRequest(data, _url, _url, false);
}
