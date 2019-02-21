function changeDebugTLS() {
  var _csrftoken = $("#csrftoken").val();
  var _value = $("#tls_debug_check").is(':checked');
  var _service = 'tls';
  
  var _url = '/settings';
  
  var data = {
      csrftoken: _csrftoken,
      service: _service,
      debughttp: _value,
  };
  sendPostRequest(data, _url, '', false);
}

function changeDebugAdmin() {
  var _csrftoken = $("#csrftoken").val();
  var _value = $("#admin_debug_check").is(':checked');
  var _service = 'admin';

  var _url = '/settings';
  
  var data = {
    csrftoken: _csrftoken,
    service: _service,
    debughttp: _value,
  };
  sendPostRequest(data, _url, '', false);
}