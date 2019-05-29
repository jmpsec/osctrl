function createContext() {
  $("#createContextModal").modal();
}

function confirmCreateContext() {
  var _csrftoken = $("#csrftoken").val();

  var _url = window.location.pathname;

  var _name = $("#context_name").val();
  var _type = $("#context_type").val();
  var _hostname = $("#context_host").val();
  var _icon = $("#context_icon").val();

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

function confirmDeleteContext(_context) {
  var modal_message = 'Are you sure you want to delete the context ' + _context + '?';
  $("#confirmModalMessage").text(modal_message);
  $('#confirm_action').click(function () {
    $('#confirmModal').modal('hide');
    deleteContext(_context);
  });
  $("#confirmModal").modal();
}

function deleteContext(_context) {
  var _csrftoken = $("#csrftoken").val();

  var _url = window.location.pathname;

  var data = {
    csrftoken: _csrftoken,
    action: 'delete',
    name: _context,
  };
  sendPostRequest(data, _url, _url, false);
}

function changeDebugHTTP(_context) {
  var _csrftoken = $("#csrftoken").val();
  var _value = $("#" + _context + "_debug_check").is(':checked');

  var _url = window.location.pathname;

  var data = {
    csrftoken: _csrftoken,
    action: 'debug',
    debughttp: _value,
    name: _context,
  };
  sendPostRequest(data, _url, '', false);
}
