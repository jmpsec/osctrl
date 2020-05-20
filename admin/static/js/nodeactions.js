function confirmRemoveNodes(_uuids) {
  var modal_message = 'Are you sure you want to remove ' + _uuids.length + ' node(s)?';
  if (_uuids.length === 1) {
    modal_message = 'Are you sure you want to remove this node?';
  }
  $("#confirmModalMessage").text(modal_message);
  $('#confirm_action').click(function () {
    $('#confirmModal').modal('hide');
    removeNodes(_uuids);
  });
  $("#confirmModal").modal();
}

function removeNodes(_uuids) {
  var _csrftoken = $("#csrftoken").val();

  var _url = '/node/actions';
  var data = {
    csrftoken: _csrftoken,
    uuids: _uuids,
    action: 'delete'
  };
  sendPostRequest(data, _url, '/', true);
}

function nodesView(environment) {
  window.location.href = '/environment/' + environment + '/active';
}

function refreshCurrentNode() {
  location.reload();
}

function queryNodes(_uuids) {
  var _csrftoken = $("#csrftoken").val();
  var _query = $("#query").val();
  // Make sure semicolon always in the query
  if (_query.slice(-1) !== ';') {
    _query = _query + ';';
  }
  var _url = '/query/run';
  var data = {
    csrftoken: _csrftoken,
    environment: "",
    platform: "",
    uuid_list: _uuids,
    host_list: [],
    query: _query,
    repeat: 0
  };
  sendPostRequest(data, _url, '', true);
}

function showQueryNodes(_uuids) {
  $('#query_action').click(function () {
    $('#queryModal').modal('hide');
    queryNodes(_uuids);
  });
  $("#queryModal").modal();
}

function carveFiles(_uuids) {
  var _csrftoken = $("#csrftoken").val();
  var _carve = $("#carve").val();

  var _url = '/carves/run';
  var data = {
    csrftoken: _csrftoken,
    environment: "",
    platform: "",
    uuid_list: _uuids,
    host_list: [],
    path: _carve,
    repeat: 0
  };
  sendPostRequest(data, _url, '', true);
}

function showCarveFiles(_uuids) {
  $('#carve_action').click(function () {
    $('#carveModal').modal('hide');
    carveFiles(_uuids);
  });
  $("#carveModal").modal();
}

function changeBackValue(table_id, range_input, range_output) {
  range_output.value = range_input.value;
  var table = $('#' + table_id).DataTable();
  var _url = table.ajax.url();
  table.ajax.url(_url.split('seconds=')[0] + 'seconds=' + (range_output.value * 3600));
}

function tagNodes(_uuids) {
  var _csrftoken = $("#csrftoken").val();
  var _tags = $("#modal_tags").val();
  var _url = '/tags/nodes';
  var data = {
    csrftoken: _csrftoken,
    uuids: _uuids,
    tags: _tags,
    action: 'tag'
  };
  sendPostRequest(data, _url, window.location, true);
}

function showTagNodes(_uuids, _tags) {
  $('#tag_action').click(function () {
    $('#tagModal').modal('hide');
    tagNodes(_uuids);
  });
  $('#modal_tags').val(null).trigger('change');
  $("#tagModal").modal();
}
