/* JS functions for different actions */

function confirmRemoveNode(_uuid) {
  var modal_message = 'Are you sure you want to remove this node?';
  $("#confirmModalMessage").text(modal_message);
  $('#confirm_action').click(function() {
    $('#confirmModal').modal('hide');
    removeNode(_uuid);
  });
  $("#confirmModal").modal();
}

function confirmRemoveNodes(_uuids) {
  var modal_message = 'Are you sure you want to remove ' + _uuids.length + ' node(s)?';
  $("#confirmModalMessage").text(modal_message);
  $('#confirm_action').click(function() {
    $('#confirmModal').modal('hide');
    removeNodes(_uuids);
  });
  $("#confirmModal").modal();
}

function removeNode(_uuid) {
  var _csrftoken = $("#csrftoken").val();
  
  var _url = '/action/' + _uuid;
  var data = {
      csrftoken: _csrftoken,
      action: 'delete'
  };
  sendPostRequest(data, _url, false, true);
}

function removeNodes(_uuids) {
  var _csrftoken = $("#csrftoken").val();
  
  var _url = '/actions';
  var data = {
      csrftoken: _csrftoken,
      uuids: _uuids, 
      action: 'delete'
  };
  sendPostRequest(data, _url, false, true);
}

function nodesView(context) {
  window.location.href = '/context/' + context + '/active';
}

function refreshCurrentNode() {
  location.reload();
}

function refreshTableNow(table_id) {
  var table = $('#' + table_id).DataTable();
  table.ajax.reload();
  return;
}

function queryNode(_uuid) {
  var _csrftoken = $("#csrftoken").val();
  var _query = $("#query").val();

  // Make sure semicolon always in the query
  if (_query.slice(-1) !== ';') {
    _query = _query + ';';
  }
  
  var _url = '/query/run';
  var data = {
      csrftoken: _csrftoken,
      context: "",
      platform: "",
      uuid_list: [_uuid],
      host_list: [],
      query: _query,
      repeat: 0
  };
  sendPostRequest(data, _url, false, true);
}

function queryNodes(_uuids) {
  var _csrftoken = $("#csrftoken").val();
  var _query = $("#query").val();
  
  var _url = '/query/run';
  var data = {
      csrftoken: _csrftoken,
      context: "",
      platform: "",
      uuid_list: _uuids,
      host_list: [],
      query: _query,
      repeat: 0
  };
  sendPostRequest(data, _url, false, true);
}

function showQueryNode(_uuid) {
  $('#query_action').click(function() {
    $('#queryModal').modal('hide');
    queryNode(_uuid);
  });
  $("#queryModal").modal();
}

function showQueryNodes(_uuids) {
  $('#query_action').click(function() {
    $('#queryModal').modal('hide');
    queryNodes(_uuids);
  });
  $("#queryModal").modal();
}