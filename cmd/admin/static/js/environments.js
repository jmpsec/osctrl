function createEnvironment() {
  $("#createEnvironmentModal").modal();
}

function confirmCreateEnvironment() {
  var _csrftoken = $("#csrftoken").val();

  var _url = window.location.pathname;

  var _name = $("#environment_name").val();
  var _type = $("#environment_type").val();
  var _hostname = $("#environment_host").val();
  var _icon = $("#environment_icon").val();

  var data = {
    csrftoken: _csrftoken,
    action: 'create',
    name: _name,
    type: _type,
    hostname: _hostname,
    icon: _icon,
  };
  sendPostRequest(data, _url, _url, false);
}

function confirmDeleteEnvironment(_env) {
  var modal_message = 'Are you sure you want to delete the environment ' + _env + '?';
  $("#confirmModalMessage").text(modal_message);
  $('#confirm_action').click(function () {
    $('#confirmModal').modal('hide');
    deleteEnvironment(_env);
  });
  $("#confirmModal").modal();
}

function deleteEnvironment(_env) {
  var _csrftoken = $("#csrftoken").val();

  var _url = window.location.pathname;

  var data = {
    csrftoken: _csrftoken,
    action: 'delete',
    name: _env,
  };
  sendPostRequest(data, _url, _url, false);
}

function changeDebugHTTP(_env) {
  var _csrftoken = $("#csrftoken").val();
  var _value = $("#" + _env + "_debug_check").is(':checked');

  var _url = window.location.pathname;

  var data = {
    csrftoken: _csrftoken,
    action: 'debug',
    debughttp: _value,
    name: _env,
  };
  sendPostRequest(data, _url, '', false);
}
