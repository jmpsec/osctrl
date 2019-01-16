function sendPostRequest(req_data, req_url, redir) {
  $.ajax({
    url: req_url,
    dataType: 'json',
    type: 'POST',
    contentType: 'application/json',
    data: JSON.stringify(req_data),
    processData: false,
    success: function(data, textStatus, jQxhr){
      console.log('OK');
      if (redir) {
        var redirection = (req_url.split("/").pop() === "run") ? "active" : req_url.split("/").pop();
        window.location.replace(redirection);
      }
    },
    error: function(jqXhr, textStatus, errorThrown){
      var _clientmsg = 'Client: ' + errorThrown;
      var _serverJSON = $.parseJSON(jqXhr.responseText);
      var _servermsg = 'Server: ' + _serverJSON.message;
      $("#errorModalMessageClient").text(_clientmsg);
      console.log(_clientmsg);
      $("#errorModalMessageServer").text(_servermsg);
      $("#errorModal").modal();
    }
  });
}

function sendQuery() {
  var _csrftoken = $("#csrftoken").val(); 
  var _context = $('#target_context_switch').prop('checked') ? $("#target_context").val() : "";
  var _platform = $('#target_platform_switch').prop('checked') ? $("#target_platform").val() : "";
  var _uuid_list = $('#target_uuids_switch').prop('checked') ? $("#target_uuids").val() : [];
  var _host_list = $('#target_hosts_switch').prop('checked') ? $("#target_hosts").val() : [];
  var _repeat = $('#target_repeat').prop('checked') ? 1 : 0;
  var editor = $('.CodeMirror')[0].CodeMirror;
  var _query = editor.getValue();
  
  var _url = '/query/run';
  var data = {
      csrftoken: _csrftoken,
      context: _context,
      platform: _platform,
      uuid_list: _uuid_list,
      host_list: _host_list,
      query: _query,
      repeat: _repeat
  };
  sendPostRequest(data, _url, true);
}

function clearQuery() {
  var editor = $('.CodeMirror')[0].CodeMirror;
  editor.setValue("");
}

function setQuery(query) {
  var editor = $('.CodeMirror')[0].CodeMirror;
  editor.setValue(query);
}

$("#query").keyup(function(event) {
  if (event.keyCode === 13) {
      $("#query_button").click();
  }
});

function deleteQueries(_names) {
  actionQueries('delete', _names);
}

function completeQueries(_names) {
  actionQueries('complete', _names);
}

function actionQueries(_action, _names) {
  var _csrftoken = $("#csrftoken").val();
  
  var _url = '/query/actions';
  var data = {
      csrftoken: _csrftoken,
      names: _names,
      action: _action
  };
  sendPostRequest(data, _url, false);
}

function confirmDeleteQueries(_names) {
  var modal_message = 'Are you sure you want to delete ' + _names.length + ' query(s)?';
  $("#confirmModalMessage").text(modal_message);
  $('#confirm_action').click(function() {
    $('#confirmModal').modal('hide');
    deleteQueries(_names);
  });
  $("#confirmModal").modal();
}

function refreshTableNow(table_id) {
  var table = $('#' + table_id).DataTable();
  table.ajax.reload();
}