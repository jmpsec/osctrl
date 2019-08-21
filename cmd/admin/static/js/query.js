function sendQuery() {
  var _csrftoken = $("#csrftoken").val();
  var _env_list = $("#target_env").val();
  var _platform_list = $("#target_platform").val();
  var _uuid_list = $("#target_uuids").val();
  var _host_list = $("#target_hosts").val();
  var _repeat = $('#target_repeat').prop('checked') ? 1 : 0;
  var editor = $('.CodeMirror')[0].CodeMirror;
  var _query = editor.getValue();

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
  // Making sure query isn't empty
  console.log(_query);
  if (_query === "") {
    $("#warningModalMessage").text("Query can not be empty");
    $("#warningModal").modal();
    return;
  }
  // Make sure semicolon always in the query
  if (_query.slice(-1) !== ';') {
    _query = _query + ';';
  }
  var _url = '/query/run';
  var data = {
    csrftoken: _csrftoken,
    environment_list: _env_list,
    platform_list: _platform_list,
    uuid_list: _uuid_list,
    host_list: _host_list,
    query: _query,
    repeat: _repeat
  };
  sendPostRequest(data, _url, '/query/list', false);
}

function clearQuery() {
  var editor = $('.CodeMirror')[0].CodeMirror;
  editor.setValue("");
}

function setQuery(query) {
  var editor = $('.CodeMirror')[0].CodeMirror;
  editor.setValue(query);
}

$("#query").keyup(function (event) {
  if (event.keyCode === 13) {
    $("#query_button").click();
  }
});

function deleteQueries(_names) {
  actionQueries('delete', _names, window.location.pathname);
}

function completeQueries(_names) {
  actionQueries('complete', _names, '/query/list');
}

function activateQueries(_names) {
  actionQueries('activate', _names, '/query/list');
}

function actionQueries(_action, _names, _redir) {
  var _csrftoken = $("#csrftoken").val();

  var _url = '/query/actions';
  var data = {
    csrftoken: _csrftoken,
    names: _names,
    action: _action
  };
  sendPostRequest(data, _url, _redir, false);
}

function confirmDeleteQueries(_names) {
  var modal_message = 'Are you sure you want to delete ' + _names.length + ' query(s)?';
  $("#confirmModalMessage").text(modal_message);
  $('#confirm_action').click(function () {
    $('#confirmModal').modal('hide');
    deleteQueries(_names);
  });
  $("#confirmModal").modal();
}
