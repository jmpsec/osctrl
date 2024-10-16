function sendQuery(_queryUrl, _redir) {
  var _csrftoken = $("#csrftoken").val();
  var _env_list = $("#target_env").val();
  var _platform_list = $("#target_platform").val();
  var _uuid_list = $("#target_uuids").val();
  var _host_list = $("#target_hosts").val();
  var _exp_hours = parseInt($("#expiration_hours").val());
  var _query_name = $("#save_query_name").val();
  var _query_save = $("#save_query_check").is(":checked") ? true : false;
  var editor = $(".CodeMirror")[0].CodeMirror;
  var _query = editor.getValue();

  // Making sure targets are specified
  if (
    _env_list.length === 0 &&
    _platform_list.length === 0 &&
    _uuid_list.length === 0 &&
    _host_list.length === 0
  ) {
    $("#warningModalMessage").text("No targets have been specified");
    $("#warningModal").modal();
    return;
  }
  // Check if all environments have been selected
  if (_env_list.includes("all_environments_99")) {
    _env_list = [];
    $("#target_env option").each(function () {
      if ($(this).val() !== "" && $(this).val() !== "all_environments_99") {
        _env_list.push($(this).val());
      }
    });
  }
  // Check if all platforms have been selected
  if (_platform_list.includes("all_platforms_99")) {
    _platform_list = [];
    $("#target_platform option").each(function () {
      if ($(this).val() !== "" && $(this).val() !== "all_platforms_99") {
        _platform_list.push($(this).val());
      }
    });
  }
  // If we are saving the query, name can not be emtpy
  if (_query_save && _query_name === "") {
    $("#warningModalMessage").text("Query name can not be empty");
    $("#warningModal").modal();
    return;
  }
  // Making sure query isn't empty
  console.log(_query);
  if (_query === "") {
    $("#warningModalMessage").text("Query can not be empty");
    $("#warningModal").modal();
    return;
  }
  // Make sure semicolon always in the query
  if (_query.slice(-1) !== ";") {
    _query = _query + ";";
  }
  var data = {
    csrftoken: _csrftoken,
    environment_list: _env_list,
    platform_list: _platform_list,
    uuid_list: _uuid_list,
    host_list: _host_list,
    save: _query_save,
    name: _query_name,
    query: _query,
    exp_hours: _exp_hours,
  };
  sendPostRequest(data, _queryUrl, _redir, false);
}

function clearQuery() {
  var editor = $(".CodeMirror")[0].CodeMirror;
  editor.setValue("");
}

function setQuery(query) {
  var editor = $(".CodeMirror")[0].CodeMirror;
  editor.setValue(query);
}

$("#query").keyup(function (event) {
  if (event.keyCode === 13) {
    $("#query_button").click();
  }
});

function deleteQueries(_names, _url) {
  actionQueries("delete", _names, _url, window.location.pathname);
}

function deleteSavedQueries(_names, _url) {
  actionQueries("saved_delete", _names, _url, window.location.pathname);
}

function completeQueries(_names, _url, _redir) {
  actionQueries("complete", _names, _url, _redir);
}

function actionQueries(_action, _names, _url, _redir) {
  var _csrftoken = $("#csrftoken").val();

  var data = {
    csrftoken: _csrftoken,
    names: _names,
    action: _action,
  };
  sendPostRequest(data, _url, _redir, false);
}

function confirmDeleteQueries(_names) {
  var modal_message =
    "Are you sure you want to delete " + _names.length + " query(s)?";
  $("#confirmModalMessage").text(modal_message);
  $("#confirm_action").click(function () {
    $("#confirmModal").modal("hide");
    deleteQueries(_names);
  });
  $("#confirmModal").modal();
}

function confirmDeleteSavedQueries(_names, _url) {
  var modal_message =
    "Are you sure you want to delete " + _names.length + " query(s)?";
  $("#confirmModalMessage").text(modal_message);
  $("#confirm_action").click(function () {
    $("#confirmModal").modal("hide");
    deleteSavedQueries(_names, _url);
  });
  $("#confirmModal").modal();
}

function queryResultLink(link, query, url) {
  var external_link =
    '<a href="' +
    link +
    '" _target="_blank" rel="noopener noreferrer"><i class="fas fa-external-link-alt"></i></a>';
  return (
    '<span class="query-link"><a href="' +
    url +
    '">' +
    query +
    "</a> - " +
    external_link +
    "</span> "
  );
}

function toggleSaveQuery() {
  $("#save_query_name").val("");
  if ($("#save_query_check").is(":checked")) {
    $("#save_query_name").removeAttr("readonly");
    $("#collapseName").removeClass("collapse");
    $("#save_query_name").focus();
  } else {
    $("#save_query_name").attr("readonly", true);
    $("#collapseName").addClass("collapse");
  }
}
