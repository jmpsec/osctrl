function sendCarve() {
  var _csrftoken = $("#csrftoken").val();
  var _env = $("#target_env").val();
  var _platform = $("#target_platform").val();
  var _uuid_list = $("#target_uuids").val();
  var _host_list = $("#target_hosts").val();
  var _repeat = $('#target_repeat').prop('checked') ? 1 : 0;
  var _path = $("#carve").val();

  // Making sure targets are specified
  if (_env === "" && _platform === "" && _uuid_list.length === 0 && _host_list.length === 0) {
    $("#warningModalMessage").text("No targets have been specified");
    $("#warningModal").modal();
    return;
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
    environment_list: _env,
    platform_list: _platform,
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
