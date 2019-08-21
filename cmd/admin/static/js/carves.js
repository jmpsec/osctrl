function sendCarve() {
  var _csrftoken = $("#csrftoken").val();
  var _env_list = $("#target_env").val();
  var _platform_list = $("#target_platform").val();
  var _uuid_list = $("#target_uuids").val();
  var _host_list = $("#target_hosts").val();
  var _repeat = $('#target_repeat').prop('checked') ? 1 : 0;
  var _path = $("#carve").val();

  // Making sure targets are specified
  if (_env_list.length === 0 && _platform_list.length === 0 && _uuid_list.length === 0 && _host_list.length === 0) {
    $("#warningModalMessage").text("No targets have been specified");
    $("#warningModal").modal();
    return;
  }
  // Check if all environments have been selected
  if (_env_list.includes("all_environments_99")) {
    _env_list = [];
    $('#target_env option').each(function () {
      if ($(this).val() !== "" && $(this).val() !== "all_environments_99") {
        _env_list.push($(this).val());
      }
    });
  }
  // Check if all platforms have been selected
  if (_platform_list.includes("all_platforms_99")) {
    _platform_list = [];
    $('#target_platform option').each(function () {
      if ($(this).val() !== "" && $(this).val() !== "all_platforms_99") {
        _platform_list.push($(this).val());
      }
    });
  }
  // Making sure path isn't empty
  console.log(_path);
  if (_path === "") {
    $("#warningModalMessage").text("Carve path can not be empty");
    $("#warningModal").modal();
    return;
  }
  var _url = '/carves/run';
  var data = {
    csrftoken: _csrftoken,
    environment_list: _env_list,
    platform_list: _platform_list,
    uuid_list: _uuid_list,
    host_list: _host_list,
    path: _path,
    repeat: _repeat
  };
  sendPostRequest(data, _url, '/carves/list', false);
}

function clearCarve() {
  $("#carve").val("");
}

$("#carve").keyup(function (event) {
  if (event.keyCode === 13) {
    $("#carve_button").click();
  }
});

function deleteCarves(_names) {
  actionQueries('delete', _names, window.location.pathname);
}

function confirmDeleteCarves(_names) {
  var modal_message = 'Are you sure you want to delete ' + _names.length + ' carve(s)?';
  $("#confirmModalMessage").text(modal_message);
  $('#confirm_action').click(function () {
    $('#confirmModal').modal('hide');
    deleteCarves(_names);
  });
  $("#confirmModal").modal();
}

function deleteCarve(_ids) {
  actionCarves('delete', _ids, window.location.pathname);
}

function confirmDeleteCarve(_ids) {
  var modal_message = 'Are you sure you want to delete this carve?';
  $("#confirmModalMessage").text(modal_message);
  $('#confirm_action').click(function () {
    $('#confirmModal').modal('hide');
    deleteCarve(_ids);
  });
  $("#confirmModal").modal();
}

function actionCarves(_action, _ids, _redir) {
  var _csrftoken = $("#csrftoken").val();

  var _url = '/carves/actions';
  var data = {
    csrftoken: _csrftoken,
    ids: _ids,
    action: _action
  };
  sendPostRequest(data, _url, _redir, false);
}

function downloadCarve(_sessionid) {
  location.href = "/carves/download/" + _sessionid;
}

function refreshCarveDetails() {
  location.reload();
}
