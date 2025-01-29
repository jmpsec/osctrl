function saveB64Blob(editor_id, blob_key, header_id) {
  var _csrftoken = $("#csrftoken").val();
  var _editor = $('#' + editor_id).data('CodeMirrorInstance');
  var _blob = _editor.getValue();

  var _url = window.location.pathname;

  var data = {
    csrftoken: _csrftoken,
    [blob_key]: btoa(_blob),
  };
  sendPostRequest(data, _url, _url, true);
  $('#' + header_id).removeClass("bg-changed");
}

function saveConfiguration() {
  saveB64Blob('final_conf', 'configuration', 'configuration_header');
}

function saveOptions() {
  saveB64Blob('options_conf', 'options', 'options_header');
}

function saveSchedule() {
  saveB64Blob('schedule_conf', 'schedule', 'schedule_header');
}

function savePacks() {
  saveB64Blob('packs_conf', 'packs', 'packs_header');
}

function saveDecorators() {
  saveB64Blob('decorators_conf', 'decorators', 'decorators_header');
}

function saveATC() {
  saveB64Blob('atc_conf', 'atc', 'atc_header');
}

function addQuerySchedule() {
  $("#addquery_action").click(function () {
    $("#addQueryModal").modal("hide");
    confirmAddQuerySchedule();
  });
  $("#query_name").val("");
  $("#query_sql").val("");
  $("#query_interval").val("");
  $("#addQueryModal").modal();
}

function confirmAddQuerySchedule() {
  var _editor = $("#schedule_conf").data("CodeMirrorInstance");
  var _schedule = _editor.getValue();
  var obj = JSON.parse(_schedule);
  var _query = {
    query: $("#query_sql").val(),
    interval: parseInt($("#query_interval").val()),
  };
  obj[$("#query_name").val()] = _query;
  _editor.setValue(JSON.stringify(obj, null, "\t"));
}

function addOsqueryOption() {
  $("#addoption_action").click(function () {
    $("#addOptionModal").modal("hide");
    confirmAddOsqueryOption();
  });
  $("#option_name").val("");
  $("#option_value").val("");
  $("#addOptionModal").modal();
}

function confirmAddOsqueryOption() {
  var _editor = $("#options_conf").data("CodeMirrorInstance");
  var _options = _editor.getValue();
  var obj = JSON.parse(_options);
  if ($("#option_type").val() === "boolean") {
    if ($("#option_value").val().toLowerCase() === "true") {
      obj[$("#option_name").val()] = true;
    } else {
      obj[$("#option_name").val()] = false;
    }
  }
  if ($("#option_type").val() === "integer") {
    obj[$("#option_name").val()] = parseInt($("#option_value").val());
  }
  if ($("#option_type").val() === "string") {
    obj[$("#option_name").val()] = $("#option_value").val();
  }
  if ($("#option_name").val() === "" || $("#option_value").val() === null) {
    return;
  }
  _editor.setValue(JSON.stringify(obj, null, "\t"));
}

function saveIntervals() {
  var _csrftoken = $("#csrftoken").val();
  var _config = $("#conf_range").val();
  var _log = $("#logging_range").val();
  var _query = $("#query_range").val();

  var _url = '/intervals/' + window.location.pathname.split('/').pop();

  var data = {
    csrftoken: _csrftoken,
    config: parseInt(_config),
    log: parseInt(_log),
    query: parseInt(_query),
  };
  sendPostRequest(data, _url, '', true);
  $('#intervals_header').removeClass("bg-changed");
}

function changeIntervalValue(range_input, range_output) {
  range_output.value = range_input.value;
  $('#intervals_header').addClass("bg-changed");
}

function lineCharPosition(_pos) {
  var line = 0;
  var ttl = 0;
  $('.CodeMirror-line').each(function () {
    //console.log('Line ' + line);
    var l = $(this).text().length;
    ttl += l;
    if (ttl >= _pos) {
      return 'line ' + line;
    }
    line++;
  });
  return 'line ' + line;
}
